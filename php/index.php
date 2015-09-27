<?php
require_once 'vendor/autoload.php';

xhprof_enable(XHPROF_FLAGS_CPU + XHPROF_FLAGS_MEMORY);
register_shutdown_function(function() {
    $xhprof_data = xhprof_disable();
    $XHPROF_ROOT = dirname(__FILE__);
    include_once $XHPROF_ROOT . "/xhprof-0.9.3/xhprof_lib/utils/xhprof_lib.php";
    include_once $XHPROF_ROOT . "/xhprof-0.9.3/xhprof_lib/utils/xhprof_runs.php";

    $xhprof_runs = new XHProfRuns_Default();
    $xhprof_runs->save_run($xhprof_data, "xhprof_testing", time());
});

date_default_timezone_set('Asia/Tokyo');
mb_internal_encoding('UTF-8');

class Isucon5View extends \Slim\View
{
    protected $layout = 'layout.php';

    public function setLayout($layout)
    {
        $this->layout = $layout;
    }

    public function render($template, $data = NULL)
    {
        if ($this->layout) {
            $_html = parent::render($template);
            $this->set('_html', $_html);
            $template = $this->layout;
            $this->layout = null;
        }
        return parent::render($template);
    }
}

$app = new \Slim\Slim(array(
    'view' => new Isucon5View(),
    'db' => array(
        'host' => getenv('ISUCON5_DB_HOST') ?: 'localhost',
        'port' => (int)getenv('ISUCON5_DB_PORT') ?: 3306,
        'username' => getenv('ISUCON5_DB_USER') ?: 'root',
        'password' => getenv('ISUCON5_DB_PASSWORD'),
        'database' => getenv('ISUCON5_DB_NAME') ?: 'isucon5q'
    ),
    'cookies.encrypt' => true,
));

$app->add(new \Slim\Middleware\SessionCookie(array(
    'secret' => getenv('ISUCON5_SESSION_SECRET') ?: 'beermoris',
    'expires' => 0,
)));

function abort_authentication_error()
{
    global $app;
    $_SESSION['user_id'] = null;
    $app->view->setLayout(null);
    $app->render('login.php', array('message' => 'ログインに失敗しました'), 401);
    $app->stop();
}

function abort_permission_denied()
{
    global $app;
    $app->render('error.php', array('message' => '友人のみしかアクセスできません'), 403);
    $app->stop();
}

function abort_content_not_found()
{
    global $app;
    $app->render('error.php', array('message' => '要求されたコンテンツは存在しません'), 404);
    $app->stop();
}

function h($string)
{
    echo htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

function db()
{
    global $app;
    static $db;
    if (!$db) {
        $config = $app->config('db');
        $dsn = sprintf("mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4", $config['host'], $config['port'], $config['database']);
        if ($config['host'] === 'localhost') $dsn .= ";unix_socket=/var/run/mysqld/mysqld.sock";
        $options = array(
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        );
        $db = new PDO($dsn, $config['username'], $config['password'], $options);
    }
    return $db;
}

function db_execute($query, $args = array())
{
    $stmt = db()->prepare($query);
    $stmt->execute($args);
    return $stmt;
}

function redis() {
    static $redis;
    if (!$redis) {
        $redis = new Redis();
        $redis->pconnect('/tmp/redis.sock');
    }
    return $redis;
}

// メールアドレスとパスワードを指定して認証
function authenticate($email, $password)
{
    $query = <<<SQL

SELECT u.id AS id, u.account_name AS account_name, u.nick_name AS nick_name, u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
WHERE u.email = ? AND u.passhash = SHA2(CONCAT(?, s.salt), 512)

SQL;
    $result = db_execute($query, array($email, $password))->fetch();
    if (!$result) {
        abort_authentication_error();
    }
    $_SESSION['user_id'] = $result['id'];
    return $result;
}

// セッションに有効なユーザーIDが入っている場合、そのユーザーのオブジェクトを返す。
function current_user()
{
    static $user;
    if ($user) return $user;
    if (!isset($_SESSION['user_id'])) return null;
    $user = db_execute('SELECT id, account_name, nick_name, email FROM users WHERE id=?', array($_SESSION['user_id']))->fetch();
    if (!$user) {
        $_SESSION['user_id'] = null;
        abort_authentication_error();
    }
    return $user;
}

// ログインしているならtrue。セッションに有効なユーザーIDが入っているかどうか
function authenticated()
{
    global $app;
    if (!current_user()) {
        $app->redirect('/login');
    }
}

// アカウントIDを指定してユーザー情報を取得
function get_user($user_id)
{
    static $users = array();
    if (isset($users[$user_id])) {
        return $users[$user_id];
    }

    $key = 'isucon_user_id_' . $user_id;
    $cache = redis()->get($key);
    if ($cache !== false) {
        return $users[$user_id] = json_decode($cache, true);
    }

    $user = db_execute('SELECT * FROM users WHERE id = ?', array($user_id))->fetch();
    if (!$user) abort_content_not_found();

    redis()->set($key, json_encode($user));
    return $users[$user_id] = $user;
}

// アカウント名を指定してユーザー情報を取得
function user_from_account($account_name)
{
    static $users = array();
    if (isset($users[$account_name])) {
        return $users[$account_name];
    }

    $key = 'isucon_user_' . $account_name;
    $cache = redis()->get($key);
    if ($cache !== false) {
        return $users[$account_name] = json_decode($cache, true);
    }
    $user = db_execute('SELECT * FROM users WHERE account_name = ?', array($account_name))->fetch();
    if (!$user) abort_content_not_found();

    redis()->set($key, json_encode($user));
    return $users[$account_name] = $user;
}

// アカウントIDを指定してフレンドのアカウントならtrue
function is_friend($another_id)
{
    static $is_friends = array();

    $user_id = $_SESSION['user_id'];

    $one = min($user_id, $another_id);
    $another = max($user_id, $another_id);

    $key = 'isucon_user_' . $one . '_' . $another;

    if (isset($is_friends[$key])) {
        return $is_friends[$key];
    }

    $cache = redis()->get($key);
    if ($cache !== false) {
        return $is_friends[$key] = json_decode($cache, true);
    }

    $query = 'SELECT COUNT(1) AS cnt FROM relations WHERE one = ? AND another = ?';

    $cnt = db_execute($query, array($one, $another))->fetch()['cnt'];

    redis()->set($key, json_encode($cnt > 0));
    return $is_friends[$key] = $cnt > 0;
}

// アカウント名を指定してフレンドのアカウントならtrue
function is_friend_account($account_name)
{
    return is_friend(user_from_account($account_name)['id']);
}

// 自分かフレンドならtrue
function permitted($another_id)
{
    return $another_id == current_user()['id'] || is_friend($another_id);
}

// 自分から指定ユーザーへの足跡をつける
function mark_footprint($user_id)
{
    if ($user_id != current_user()['id']) {
        $query = 'INSERT INTO footprints (user_id,owner_id) VALUES (?,?)';
        db_execute($query, array($user_id, current_user()['id']));
    }
}

// 地域一覧の取得
function prefectures()
{
    static $PREFS = array(
        '未入力',
        '北海道', '青森県', '岩手県', '宮城県', '秋田県', '山形県', '福島県', '茨城県', '栃木県', '群馬県', '埼玉県', '千葉県', '東京都', '神奈川県', '新潟県', '富山県',
        '石川県', '福井県', '山梨県', '長野県', '岐阜県', '静岡県', '愛知県', '三重県', '滋賀県', '京都府', '大阪府', '兵庫県', '奈良県', '和歌山県', '鳥取県', '島根県',
        '岡山県', '広島県', '山口県', '徳島県', '香川県', '愛媛県', '高知県', '福岡県', '佐賀県', '長崎県', '熊本県', '大分県', '宮崎県', '鹿児島県', '沖縄県'
    );
    return $PREFS;
}

function getRecentComments() {
    $cache = redis()->get('isucon_recent_comments');
    if ($cache !== false) {
        return json_decode($cache, true);
    }

    $stmt = db_execute('SELECT * FROM comments ORDER BY created_at DESC LIMIT 1000');
    $comments = [];
    while ($comment = $stmt->fetch()) {
        $comments[] = $comment;
    }
    redis()->set('isucon_recent_comments', json_encode($comments));
    return $comments;
}

function getEntry($id) {
    static $entries = [];
    if (isset($entries[$id])) {
        return $entries[$id];
    }

    $key = 'isucon_entry_' . $id;
    $cache = redis()->get($key);
    if ($cache !== false) {
        return $entries[$id] = json_decode($cache, true);
    }

    $entry = db_execute('SELECT * FROM entries WHERE id = ?', array($id))->fetch();

    redis()->set($key, json_encode($entry));
    return $entry;
}

// ログイン画面
$app->get('/login', function () use ($app) {
    $app->view->setLayout(null);
    $app->render('login.php', array('message' => '高負荷に耐えられるSNSコミュニティサイトへようこそ!'));
});

// ログイン処理
$app->post('/login', function () use ($app) {
    $params = $app->request->params();
    authenticate($params['email'], $params['password']);
    $app->redirect('/');
});

// ログアウト
$app->get('/logout', function () use ($app) {
    $_SESSION['user_id'] = null;
    $app->redirect('/login');
});

function getEntriesByUserId($userId) {
    $entries_query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5';
    $stmt = db_execute($entries_query, array($userId));
    $entries = array();
    while ($entry = $stmt->fetch()) {
        $entry['is_private'] = ($entry['private'] == 1);
        list($title, $content) = preg_split('/\n/', $entry['body'], 2);
        $entry['title'] = $title;
        $entry['content'] = $content;
        $entries[] = $entry;
    }
    return $entries;
}

function getEntriesWithCommentsByUserId($userId) {
    $query = '';
    if (permitted($userId)) {
        $query = 'SELECT id, private, body, (SELECT count(*) FROM comments WHERE entry_id = entries.id) AS comment_count, created_at FROM entries WHERE user_id = ? AND created_at > "2013-01-01" ORDER BY created_at DESC LIMIT 20';
    } else {
        $query = 'SELECT id, private, body, (SELECT count(*) FROM comments WHERE entry_id = entries.id) AS comment_count, created_at FROM entries WHERE user_id = ? AND created_at > "2013-01-01" AND private=0 ORDER BY created_at DESC LIMIT 20';
    }
    $entries = array();
    $stmt = db_execute($query, array($userId));
    while ($entry = $stmt->fetch()) {
        $entry['is_private'] = ($entry['private'] == 1);
        list($title, $content) = preg_split('/\n/', $entry['body'], 2);
        $entry['title'] = $title;
        $entry['content'] = $content;
        $entries[] = $entry;
    }
    return $entries;
}

function getCommentsForMe() {
        $comments_for_me_query = <<<SQL
SELECT c.id AS id, c.entry_id AS entry_id, c.user_id AS user_id, c.comment AS comment, c.created_at AS created_at
FROM comments c
JOIN entries e ON c.entry_id = e.id
WHERE e.user_id = ?
ORDER BY c.created_at DESC
LIMIT 10
SQL;
    return db_execute($comments_for_me_query, array(current_user()['id']))->fetchAll();
}

function getEntriesOfFriends($userId) {
    $entries_of_friends = array();
    $eof_query = <<<SQL
SELECT * FROM entries
WHERE (SELECT 1 FROM relations WHERE relations.one = entries.user_id AND relations.another = ?) = 1
ORDER BY created_at DESC LIMIT 10
SQL;
    $stmt = db_execute($eof_query, array($userId));
    while ($entry = $stmt->fetch()) {
        // if (!is_friend($entry['user_id'])) continue;
        list($title) = preg_split('/\n/', $entry['body']);
        $entry['title'] = $title;
        $entries_of_friends[] = $entry;
        // if (sizeof($entries_of_friends) >= 10) break;
    }
    return $entries_of_friends;
}

function getCommentsOfFriends() {
    $comments_of_friends = array();
    $stmt = db_execute('SELECT * FROM comments ORDER BY created_at DESC LIMIT 1000');
    while ($comment = $stmt->fetch()) {
        if (!is_friend($comment['user_id'])) continue;
        $entry = getEntry($comment['entry_id']);
        $entry['is_private'] = ($entry['private'] == 1);
        if ($entry['is_private'] && !permitted($entry['user_id'])) continue;
        $comments_of_friends[] = $comment;
        if (sizeof($comments_of_friends) >= 10) break;
    }
    return $comments_of_friends;
}

function getFriends() {
    $friends_query = 'SELECT * FROM relations WHERE one = ? ORDER BY created_at DESC';
    $friends = array();
    $stmt = db_execute($friends_query, array(current_user()['id']));
    while ($rel = $stmt->fetch()) {
        if (!isset($friends[$rel['another']])) $friends[$rel['another']] = $rel['created_at'];
    }
    return $friends;
}

function getFootpoints() {
    $query = <<<SQL
SELECT user_id, owner_id, DATE(created_at) AS date, MAX(created_at) AS updated
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 10
SQL;
    return db_execute($query, array(current_user()['id']))->fetchAll();
}

// トップページ。プロフィール･自分の最近の日記･日記へのあしあと･日記へのコメント･友だちの日記･友達のコメント
$app->get('/', function () use ($app) {
    authenticated();

    $profile = db_execute('SELECT * FROM profiles WHERE user_id = ?', array(current_user()['id']))->fetch();
    $entries = getEntriesByUserId(current_user()['id']);
    $comments_for_me = getCommentsForMe();
    $entries_of_friends = getEntriesOfFriends(current_user()['id']);
    $comments_of_friends = getCommentsOfFriends();
    $friends = getFriends();
    $footprints = getFootpoints();

    $locals = array(
        'user' => current_user(),
        'profile' => $profile,
        'entries' => $entries,
        'comments_for_me' => $comments_for_me,
        'entries_of_friends' => $entries_of_friends,
        'comments_of_friends' => $comments_of_friends,
        'friends' => $friends,
        'footprints' => $footprints
    );
    $app->render('index.php', $locals);
});

// ユーザーのプロフィールページ
$app->get('/profile/:account_name', function ($account_name) use ($app) {
    authenticated();
    $owner = user_from_account($account_name);
    $prof = db_execute('SELECT * FROM profiles WHERE user_id = ?', array($owner['id']))->fetch();
    if (!$prof) $prof = array();
    if (permitted($owner['id'])) {
        $query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5';
    } else {
        $query = 'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5';
    }
    $entries = array();
    $stmt = db_execute($query, array($owner['id']));
    while ($entry = $stmt->fetch()) {
        $entry['is_private'] = ($entry['private'] == 1);
        list($title, $content) = preg_split('/\n/', $entry['body'], 2);
        $entry['title'] = $title;
        $entry['content'] = $content;
        $entries[] = $entry;
    }
    mark_footprint($owner['id']);
    $locals = array(
        'owner' => $owner,
        'profile' => $prof,
        'entries' => $entries,
        'private' => permitted($owner['id']),
    );
    $app->render('profile.php', $locals);
});

// ユーザーのプロフィールページの更新。自分のみできる
$app->post('/profile/:account_name', function ($account_name) use ($app) {
    authenticated();
    if ($account_name != current_user()['account_name']) {
        abort_permission_denied();
    }
    $params = $app->request->params();
    $args = array($params['first_name'], $params['last_name'], $params['sex'], $params['birthday'], $params['pref']);

    $prof = db_execute('SELECT * FROM profiles WHERE user_id = ?', array(current_user()['id']))->fetch();
    if ($prof) {
      $query = <<<SQL
UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?
SQL;
      $args[] = current_user()['id'];
    } else {
      $query = <<<SQL
INSERT INTO profiles (user_id,first_name,last_name,sex,birthday,pref) VALUES (?,?,?,?,?,?)
SQL;
        array_unshift($args, current_user()['id']);
    }
    db_execute($query, $args);
    $app->redirect('/profile/'.$account_name);
});

// ユーザーの日記一覧。プライベートなものはオーナーのみが見える
$app->get('/diary/entries/:account_name', function ($account_name) use ($app) {
    authenticated();
    $owner = user_from_account($account_name);
    $entries = getEntriesWithCommentsByUserId($owner['id']);
    mark_footprint($owner['id']);
    $locals = array(
        'owner' => $owner,
        'entries' => $entries,
        'myself' => (current_user()['id'] == $owner['id']),
    );
    $app->render('entries.php', $locals);
});

// 記事の個別ページ･プライベートなものは自オーナーにだけ
$app->get('/diary/entry/:entry_id', function ($entry_id) use ($app) {
    authenticated();
    $entry = db_execute('SELECT * FROM entries WHERE id = ?', array($entry_id))->fetch();
    if (!$entry) abort_content_not_found();
    list($title, $content) = preg_split('/\n/', $entry['body'], 2);
    $entry['title'] = $title;
    $entry['content'] = $content;
    $entry['is_private'] = ($entry['private'] == 1);
    $owner = get_user($entry['user_id']);
    if ($entry['is_private'] && !permitted($owner['id'])) {
        abort_permission_denied();
    }
    $comments = db_execute('SELECT * FROM comments WHERE entry_id = ?', array($entry['id']))->fetchAll();
    mark_footprint($owner['id']);
    $locals = array(
        'owner' => $owner,
        'entry' => $entry,
        'comments' => $comments,
    );
    $app->render('entry.php', $locals);
});

// 記事の投稿
$app->post('/diary/entry', function () use ($app) {
    authenticated();
    $query = 'INSERT INTO entries (user_id, private, body) VALUES (?,?,?)';
    $params = $app->request->params();
    $title = isset($params['title']) ? $params['title'] : "タイトルなし";
    $content = isset($params['content']) ? $params['content'] : "";
    $body = $title . "\n" . $content;
    db_execute($query, array(current_user()['id'], (isset($params['private']) ? '1' : '0'), $body));
    $app->redirect('/diary/entries/'.current_user()['account_name']);
});

// 記事ID指定でコメント
$app->post('/diary/comment/:entry_id', function ($entry_id) use ($app) {
    authenticated();
    $entry = db_execute('SELECT * FROM entries WHERE id = ?', array($entry_id))->fetch();
    if (!$entry) abort_content_not_found();
    $entry['is_private'] = ($entry['private'] == 1);
    if ($entry['is_private'] && !permitted($entry['user_id'])) {
        abort_permission_denied();
    }
    $query = 'INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)';
    $params = $app->request->params();
    db_execute($query, array($entry['id'], current_user()['id'], $params['comment']));
    redis()->del('isucon_recent_comments');
    $app->redirect('/diary/entry/'.$entry['id']);
});

// あしあと一覧
$app->get('/footprints', function () use ($app) {
    authenticated();
    $query = <<<SQL
SELECT user_id, owner_id, DATE(created_at) AS date, MAX(created_at) as updated
FROM footprints
WHERE user_id = ?
GROUP BY owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 50
SQL;
    $footprints = db_execute($query, array(current_user()['id']))->fetchAll();
    $app->render('footprints.php', array('footprints' => $footprints));
});

// 友達一覧
$app->get('/friends', function () use ($app) {
    authenticated();
    $query = 'SELECT * FROM relations WHERE one = ? ORDER BY created_at DESC';
    $friends = array();
    $stmt = db_execute($query, array(current_user()['id']));
    while ($rel = $stmt->fetch()) {
        if (!isset($friends[$rel['another']])) $friends[$rel['another']] = $rel['created_at'];
    }
    $app->render('friends.php', array('friends' => $friends));
});

// 指定した相手と友だちになる
$app->post('/friends/:account_name', function ($account_name) use ($app) {
    authenticated();
    if (!is_friend_account($account_name)) {
        $user = user_from_account($account_name);
        if (!$user) abort_content_not_found();
        db_execute('INSERT INTO relations (one, another) VALUES (?,?), (?,?)', array(current_user()['id'], $user['id'], $user['id'], current_user()['id']));

        $key = 'isucon_user_' . min(current_user()['id'], $user['id']) . '_' . max(current_user()['id'], $user['id']);
        redis()->set($key, json_encode(true));
        $app->redirect('/friends');
    }
});

$app->get('/initialize', function () use ($app) {
    db_execute("DELETE FROM relations WHERE id > 500000");
    db_execute("DELETE FROM footprints WHERE id > 500000");
    db_execute("DELETE FROM entries WHERE id > 500000");
    db_execute("DELETE FROM comments WHERE id > 1500000");
    redis()->flushall();
});

$app->run();
