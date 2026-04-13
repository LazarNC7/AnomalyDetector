<?php


// Simulare baza de date in memorie 
$users = [
    ["id" => 1, "username" => "admin",   "password" => "admin123",  "email" => "admin@site.com"],
    ["id" => 2, "username" => "john",    "password" => "pass123",   "email" => "john@site.com"],
    ["id" => 3, "username" => "maria",   "password" => "maria456",  "email" => "maria@site.com"],
    ["id" => 4, "username" => "test",    "password" => "test",      "email" => "test@site.com"],
    ["id" => 5, "username" => "user1",   "password" => "user1pass", "email" => "user1@site.com"],
];

$products = [
    ["id" => 1, "name" => "Laptop Pro",     "price" => 1299.99, "desc" => "High performance laptop"],
    ["id" => 2, "name" => "Mouse Wireless", "price" => 29.99,   "desc" => "Ergonomic wireless mouse"],
    ["id" => 3, "name" => "Keyboard USB",   "price" => 49.99,   "desc" => "Mechanical keyboard"],
    ["id" => 4, "name" => "Monitor 4K",     "price" => 399.99,  "desc" => "Ultra HD display"],
    ["id" => 5, "name" => "Webcam HD",      "price" => 79.99,   "desc" => "1080p webcam"],
];

$page    = $_GET['page']    ?? 'home';
$message = "";
$results = [];

//  LOGIN (vulnerabil la SQLi — nu face sanitizare) 
$login_result = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $page === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // accepta orice daca contine ' OR '1'='1
    $sqli_bypass = preg_match("/'\s*or\s*'?1'?\s*=\s*'?1|'--|\"\s*or\s*\"|union.*select/i", $username . $password);

    if ($sqli_bypass) {
        $login_result = "success";
        $message = "Welcome, admin! (SQLi bypass detected in logs)";
    } else {
        $found = false;
        foreach ($users as $u) {
            if ($u['username'] === $username && $u['password'] === $password) {
                $found = true;
                $message = "Welcome, " . $u['username'] . "!";
                $login_result = "success";
                break;
            }
        }
        if (!$found) {
            $login_result = "fail";
            $message = "Invalid credentials.";
        }
    }
}

//  SEARCH (vulnerabil la XSS — reflecta input fara escape) 
$search_query   = $_GET['q'] ?? '';
$search_results = [];
if ($search_query !== '') {
    foreach ($products as $p) {
        if (stripos($p['name'], $search_query) !== false ||
            stripos($p['desc'], $search_query) !== false) {
            $search_results[] = $p;
        }
    }
}

//  PROFILE (vulnerabil la SQLi prin id — nu valideaza tipul) 
$profile_user   = null;
$profile_id     = $_GET['id'] ?? '';
if ($profile_id !== '' && $page === 'profile') {
    // VULNERABILITATE: accepta orice id, inclusiv ' OR 1=1--
    $sqli_in_id = preg_match("/'\s*or|union.*select|--|\#/i", $profile_id);
    if ($sqli_in_id) {
        // Simuleaza leak de date
        $profile_user = $users[0];
        $message = "[SQLi] Data leak simulated.";
    } else {
        foreach ($users as $u) {
            if ((string)$u['id'] === (string)$profile_id) {
                $profile_user = $u;
                break;
            }
        }
        if (!$profile_user) $message = "User not found.";
    }
}

//  COMMENT (vulnerabil la XSS stored simulat) 
$comment     = $_POST['comment'] ?? $_GET['comment'] ?? '';
$comment_out = '';
if ($comment !== '') {
    // VULNERABILITATE XSS: reflecta comentariul fara htmlspecialchars
    $comment_out = $comment;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MyShop — <?= htmlspecialchars($page) ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #f4f4f4; color: #333; }
        nav { background: #1a1a2e; padding: 12px 24px; display: flex; gap: 20px; align-items: center; }
        nav a { color: #e0e0e0; text-decoration: none; font-size: 14px; }
        nav a:hover { color: #fff; }
        nav .brand { color: #fff; font-weight: bold; font-size: 16px; margin-right: auto; }
        .container { max-width: 860px; margin: 40px auto; padding: 0 20px; }
        .card { background: #fff; border-radius: 8px; padding: 28px; margin-bottom: 20px;
                box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
        h1 { font-size: 22px; margin-bottom: 18px; }
        h2 { font-size: 17px; margin-bottom: 12px; color: #444; }
        label { display: block; font-size: 13px; margin-bottom: 4px; color: #555; }
        input[type=text], input[type=password], textarea {
            width: 100%; padding: 9px 12px; border: 1px solid #ddd;
            border-radius: 5px; font-size: 14px; margin-bottom: 12px; }
        button, input[type=submit] {
            background: #1a1a2e; color: #fff; border: none;
            padding: 10px 22px; border-radius: 5px; cursor: pointer; font-size: 14px; }
        button:hover { background: #16213e; }
        .msg-ok  { background: #e8f5e9; color: #2e7d32; padding: 10px 14px;
                   border-radius: 5px; margin-bottom: 14px; font-size: 14px; }
        .msg-err { background: #ffebee; color: #c62828; padding: 10px 14px;
                   border-radius: 5px; margin-bottom: 14px; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th { background: #f0f0f0; padding: 8px 12px; text-align: left; }
        td { padding: 8px 12px; border-bottom: 1px solid #eee; }
        .search-bar { display: flex; gap: 10px; margin-bottom: 16px; }
        .search-bar input { flex: 1; margin-bottom: 0; }
        .xss-output { background: #fffde7; border: 1px solid #f9a825;
                      padding: 10px 14px; border-radius: 5px; margin-top: 12px; font-size: 14px; }
        .profile-box { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 14px; }
        .profile-box span { color: #666; }
    </style>
</head>
<body>

<nav>
    <span class="brand">MyShop</span>
    <a href="?page=home">Home</a>
    <a href="?page=login">Login</a>
    <a href="?page=search">Search</a>
    <a href="?page=profile">Profile</a>
    <a href="?page=comment">Comments</a>
</nav>

<div class="container">

<?php if ($page === 'home'): ?>
    <div class="card">
        <h1>Welcome to MyShop</h1>
        <p style="color:#666; font-size:14px; margin-bottom:18px;">
            Browse our products, login to your account, or search for items.
        </p>
        <table>
            <tr><th>ID</th><th>Product</th><th>Price</th><th>Description</th></tr>
            <?php foreach ($products as $p): ?>
            <tr>
                <td><?= $p['id'] ?></td>
                <td><?= htmlspecialchars($p['name']) ?></td>
                <td>$<?= number_format($p['price'], 2) ?></td>
                <td><?= htmlspecialchars($p['desc']) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>

<?php elseif ($page === 'login'): ?>
    <div class="card">
        <h1>Login</h1>
        <?php if ($message): ?>
            <div class="<?= $login_result === 'success' ? 'msg-ok' : 'msg-err' ?>">
                <?= $message /* XSS intentionat — nu e escapuit */ ?>
            </div>
        <?php endif; ?>
        <form method="POST" action="?page=login">
            <label>Username</label>
            <input type="text" name="username"
                   value="<?= $_POST['username'] ?? '' /* XSS reflectat in value */ ?>"
                   placeholder="e.g. admin" />
            <label>Password</label>
            <input type="password" name="password" placeholder="Enter password" />
            <button type="submit">Login</button>
        </form>
        <p style="font-size:12px; color:#999; margin-top:12px;">
            Try: admin / admin123
        </p>
    </div>

<?php elseif ($page === 'search'): ?>
    <div class="card">
        <h1>Search Products</h1>
        <form method="GET" action="">
            <input type="hidden" name="page" value="search">
            <div class="search-bar">
                <input type="text" name="q"
                       value="<?= $search_query /* XSS reflectat intentionat */ ?>"
                       placeholder="Search products..." />
                <button type="submit">Search</button>
            </div>
        </form>

        <?php if ($search_query !== ''): ?>
            <!-- XSS VULNERABILITATE: search query reflectat fara escape -->
            <p style="font-size:13px; color:#666; margin-bottom:12px;">
                Results for: <?= $search_query ?>
            </p>
            <?php if ($search_results): ?>
                <table>
                    <tr><th>ID</th><th>Name</th><th>Price</th></tr>
                    <?php foreach ($search_results as $p): ?>
                    <tr>
                        <td><?= $p['id'] ?></td>
                        <td><?= htmlspecialchars($p['name']) ?></td>
                        <td>$<?= number_format($p['price'], 2) ?></td>
                    </tr>
                    <?php endforeach; ?>
                </table>
            <?php else: ?>
                <p style="color:#999; font-size:14px;">No products found.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>

<?php elseif ($page === 'profile'): ?>
    <div class="card">
        <h1>User Profile</h1>
        <form method="GET" action="">
            <input type="hidden" name="page" value="profile">
            <div class="search-bar">
                <input type="text" name="id"
                       value="<?= htmlspecialchars($profile_id) ?>"
                       placeholder="Enter user ID (1-5)" />
                <button type="submit">View</button>
            </div>
        </form>
        <?php if ($message): ?>
            <div class="<?= str_contains($message, 'SQLi') ? 'msg-err' : 'msg-ok' ?>">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>
        <?php if ($profile_user): ?>
            <div class="profile-box">
                <span>ID:</span>       <strong><?= $profile_user['id'] ?></strong>
                <span>Username:</span> <strong><?= htmlspecialchars($profile_user['username']) ?></strong>
                <span>Email:</span>    <strong><?= htmlspecialchars($profile_user['email']) ?></strong>
            </div>
        <?php endif; ?>
    </div>

<?php elseif ($page === 'comment'): ?>
    <div class="card">
        <h1>Comments</h1>
        <form method="POST" action="?page=comment">
            <label>Leave a comment</label>
            <textarea name="comment" rows="3"
                      placeholder="Write something..."><?= $comment ?></textarea>
            <button type="submit">Post</button>
        </form>
        <?php if ($comment_out !== ''): ?>
            <div class="xss-output">
                <strong>Your comment:</strong><br>
                <!-- XSS VULNERABILITATE: comentariu afisat fara escape -->
                <?= $comment_out ?>
            </div>
        <?php endif; ?>
    </div>

<?php else: ?>
    <div class="card">
        <h1>404 — Page not found</h1>
        <p style="color:#999;">The page "<?= htmlspecialchars($page) ?>" does not exist.</p>
    </div>
<?php endif; ?>

</div>
</body>
</html>