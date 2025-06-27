<!DOCTYPE html>
<html>
<head>
    <title>API Endpoint</title>
</head>
<body>
    <h1>API Endpoint</h1>
    <p>This simulates a vulnerable API endpoint.</p>
    
    <?php
    // Simulate vulnerable parameters
    if (isset($_GET['user'])) {
        echo "<p>User lookup: " . htmlspecialchars($_GET['user']) . "</p>";
        echo "<p>SQL Query would be: SELECT * FROM users WHERE username = '" . $_GET['user'] . "'</p>";
    }
    
    if (isset($_POST['data'])) {
        echo "<p>Posted data: " . htmlspecialchars($_POST['data']) . "</p>";
    }
    ?>
    
    <form method="GET">
        <label>User ID: <input type="text" name="user" value="<?php echo htmlspecialchars($_GET['user'] ?? ''); ?>"></label>
        <button type="submit">Search</button>
    </form>
</body>
</html>