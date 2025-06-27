FROM php:7.4-apache

# Install required PHP extensions and tools
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    mariadb-client \
    default-mysql-client \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install gd mysqli pdo pdo_mysql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers

# Set up DVWA (Damn Vulnerable Web Application)
RUN git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa \
    && chmod -R 777 /var/www/html/dvwa/hackable/uploads \
    && chmod -R 777 /var/www/html/dvwa/config

# Create additional vulnerable endpoints
RUN mkdir -p /var/www/html/api /var/www/html/vulnerabilities

# Create DVWA config (simplified without database)
RUN echo '<?php \
$_DVWA = array(); \
$_DVWA["default_security_level"] = "low"; \
$_DVWA["default_locale"] = "en"; \
$_DVWA["disable_authentication"] = true; \
?>' > /var/www/html/dvwa/config/config.inc.php

# Create custom vulnerable API endpoints
RUN echo '<?php \
header("Content-Type: application/json"); \
\
if (isset($_GET["user"])) { \
    $user = $_GET["user"]; \
    $query = "SELECT * FROM users WHERE username = \"" . $user . "\""; \
    echo json_encode(["query" => $query, "vulnerable" => "SQL injection possible"]); \
} \
\
if (isset($_POST["host"])) { \
    $host = $_POST["host"]; \
    $output = "ping -c 1 " . $host; \
    echo json_encode(["command" => $output, "vulnerable" => "Command injection possible"]); \
} \
\
if (isset($_POST["xml"])) { \
    $xml = $_POST["xml"]; \
    echo json_encode(["xml" => $xml, "vulnerable" => "XXE injection possible"]); \
} \
\
if (isset($_FILES["file"])) { \
    $filename = $_FILES["file"]["name"]; \
    echo json_encode(["filename" => $filename, "vulnerable" => "File upload possible"]); \
} \
?>' > /var/www/html/api/index.php

# Create additional vulnerable pages
RUN echo '<?php \
if (isset($_GET["page"])) { \
    $page = $_GET["page"]; \
    echo "Path traversal attempt: " . $page; \
} \
\
if (isset($_GET["username"])) { \
    $username = $_GET["username"]; \
    $ldap_query = "(&(uid=" . $username . "))"; \
    echo "LDAP Query: " . $ldap_query; \
} \
\
if (isset($_GET["name"])) { \
    $name = $_GET["name"]; \
    echo "Hello, " . $name . "!"; \
} \
\
if (isset($_POST["data"])) { \
    $data = $_POST["data"]; \
    echo "Deserialization attempt: " . $data; \
} \
?>' > /var/www/html/vulnerabilities/index.php

# Create Apache config
RUN echo '<VirtualHost *:80> \
    DocumentRoot /var/www/html \
    <Directory /var/www/html> \
        Options Indexes FollowSymLinks \
        AllowOverride All \
        Require all granted \
    </Directory> \
    ErrorLog ${APACHE_LOG_DIR}/error.log \
    CustomLog ${APACHE_LOG_DIR}/access.log combined \
</VirtualHost>' > /etc/apache2/sites-available/000-default.conf

# Create uploads directory
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads

# Create simple vulnerable endpoints (no database required for basic testing)
RUN echo '<?php \
echo "<h1>Vulnerable Test Application</h1>"; \
echo "<p>Welcome to the test target application.</p>"; \
echo "<ul>"; \
echo "<li><a href=\"/api/\">API Endpoints</a></li>"; \
echo "<li><a href=\"/vulnerabilities/\">Vulnerability Tests</a></li>"; \
echo "<li><a href=\"/dvwa/\">DVWA (if available)</a></li>"; \
echo "</ul>"; \
?>' > /var/www/html/index.php

# Create startup script
RUN echo '#!/bin/bash\napache2-foreground' > /start.sh && chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]