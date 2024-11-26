<?php
use \Firebase\JWT\JWT;
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;

$app = new \Slim\App;
require '../src/vendor/autoload.php';

$dbConfig = [
    'host' => 'localhost',
    'user' => 'root',
    'pass' => '',
    'name' => 'library2'
];

// JWT Token Secret Key
$secretKey = 'server_hack';

$tokenStore = [];

// Database Connection Function
function connectDB($dbConfig) {
    try {
        $pdo = new PDO("mysql:host={$dbConfig['host']};dbname={$dbConfig['name']}", $dbConfig['user'], $dbConfig['pass']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        die("Could not connect to the database: " . $e->getMessage());
    }
}

// Function to check if author exists
function authorExists($pdo, $name) {
    $sql = "SELECT * FROM authors WHERE name = :name";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['name' => $name]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Function to check if book exists
function bookExists($pdo, $title) {
    $sql = "SELECT * FROM books WHERE title = :title";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['title' => $title]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Function to check if book-author relationship exists
function bookAuthorExists($pdo, $bookId, $authorId) {
    $sql = "SELECT * FROM books_authors WHERE book_id = :book_id AND author_id = :author_id";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['book_id' => $bookId, 'author_id' => $authorId]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// JWT Token Creation Function
function createToken() {
    global $secretKey;
    $issuedAt = time();
    $expiry = $issuedAt + 3600;
    $payload = [
        'iss' => 'http://library.org',
        'aud' => 'http://library.com',
        'iat' => $issuedAt,
        'exp' => $expiry
    ];
    return JWT::encode($payload, $secretKey, 'HS256');
}

// Middleware for Token Validation
function tokenMiddleware($request, $response, $next) {
    global $secretKey, $tokenStore;
    
    $authHeader = $request->getHeader('Authorization');
    if (!$authHeader) {
        return $response->withStatus(401)->write('Unauthorized - Missing Token');
    }

    $token = trim(explode("Bearer", $authHeader[0])[1]);

    try {
        $decoded = JWT::decode($token, $secretKey, ['HS256']);
        if ($decoded && !$tokenStore[$token]['used']) {
            $response = $next($request, $response);
            return $response;
        } else {
            return $response->withStatus(401)->write('Unauthorized - Invalid Token');
        }
    } catch (Exception $e) {
        return $response->withStatus(401)->write('Unauthorized - Token Error');
    }
}

// User Sign-Up
$app->post('/user/signup', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $data = $request->getParsedBody();
    $username = $data['username'];
    $password = password_hash($data['password'], PASSWORD_DEFAULT);

    $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['username' => $username, 'password' => $password]);
        return $response->withJson(['status' => 'success', 'message' => 'User registered successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
});

// User Login
$app->post('/user/login', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $data = $request->getParsedBody();
    $username = $data['username'];
    $password = $data['password'];

    $sql = "SELECT * FROM users WHERE username = :username";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        $token = createToken();
        global $tokenStore;
        $tokenStore[$token] = ['used' => false];
        return $response->withJson(['status' => 'success', 'token' => $token]);
    } else {
        return $response->withJson(['status' => 'fail', 'message' => 'Invalid credentials']);
    }
});

// Add Author
$app->post('/authors', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $data = $request->getParsedBody();
    $name = $data['name'];

    // Check if author exists
    if (authorExists($pdo, $name)) {
        return $response->withJson(['status' => 'fail', 'message' => 'Author already exists']);
    }

    $sql = "INSERT INTO authors (name) VALUES (:name)";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['name' => $name]);
        return $response->withJson(['status' => 'success', 'message' => 'Author added successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Delete Author
$app->delete('/authors/{id}', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $id = $request->getAttribute('id');

    $sql = "DELETE FROM authors WHERE id = :id";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['id' => $id]);
        return $response->withJson(['status' => 'success', 'message' => 'Author deleted successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Update Author
$app->put('/authors/{id}', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $id = $request->getAttribute('id');
    $data = $request->getParsedBody();
    $name = $data['name'];

    $sql = "UPDATE authors SET name = :name WHERE id = :id";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['name' => $name, 'id' => $id]);
        return $response->withJson(['status' => 'success', 'message' => 'Author updated successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Add Book
$app->post('/books', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $data = $request->getParsedBody();
    $title = $data['title'];
    $authorId = $data['author_id'];

    // Check if book exists
    if (bookExists($pdo, $title)) {
        return $response->withJson(['status' => 'fail', 'message' => 'Book already exists']);
    }

    $sql = "INSERT INTO books (title, author_id) VALUES (:title, :author_id)";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['title' => $title, 'author_id' => $authorId]);
        return $response->withJson(['status' => 'success', 'message' => 'Book added successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Delete Book
$app->delete('/books/{id}', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $id = $request->getAttribute('id');

    $sql = "DELETE FROM books WHERE id = :id";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['id' => $id]);
        return $response->withJson(['status' => 'success', 'message' => 'Book deleted successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Update Book
$app->put('/books/{id}', function (Request $request, Response $response) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $id = $request->getAttribute('id');
    $data = $request->getParsedBody();
    $title = $data['title'];
    $authorId = $data['author_id'];

    $sql = "UPDATE books SET title = :title, author_id = :author_id WHERE id = :id";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['title' => $title, 'author_id' => $authorId, 'id' => $id]);
        return $response->withJson(['status' => 'success', 'message' => 'Book updated successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Add Book-Author Relationship
$app->post('/books/{bookId}/authors/{authorId}', function (Request $request, Response $response, $args) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $bookId = $args['bookId'];
    $authorId = $args['authorId'];

    // Check if relationship already exists
    if (bookAuthorExists($pdo, $bookId, $authorId)) {
        return $response->withJson(['status' => 'fail', 'message' => 'Book-Author relationship already exists']);
    }

    $sql = "INSERT INTO books_authors (book_id, author_id) VALUES (:book_id, :author_id)";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['book_id' => $bookId, 'author_id' => $authorId]);
        return $response->withJson(['status' => 'success', 'message' => 'Book-Author relationship added successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Delete Book-Author Relationship
$app->delete('/books/{bookId}/authors/{authorId}', function (Request $request, Response $response, $args) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $bookId = $args['bookId'];
    $authorId = $args['authorId'];

    $sql = "DELETE FROM books_authors WHERE book_id = :book_id AND author_id = :author_id";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['book_id' => $bookId, 'author_id' => $authorId]);
        return $response->withJson(['status' => 'success', 'message' => 'Book-Author relationship deleted successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');

// Update Book-Author Relationship
$app->put('/books/{bookId}/authors/{authorId}', function (Request $request, Response $response, $args) use ($dbConfig) {
    $pdo = connectDB($dbConfig);
    $bookId = $args['bookId'];
    $authorId = $args['authorId'];
    $data = $request->getParsedBody();
    $newAuthorId = $data['author_id'];

    // Optionally check if new relationship already exists
    if (bookAuthorExists($pdo, $bookId, $newAuthorId)) {
        return $response->withJson(['status' => 'fail', 'message' => 'Book-Author relationship already exists']);
    }

    $sql = "UPDATE books_authors SET author_id = :new_author_id WHERE book_id = :book_id AND author_id = :author_id";
    $stmt = $pdo->prepare($sql);
    try {
        $stmt->execute(['new_author_id' => $newAuthorId, 'book_id' => $bookId, 'author_id' => $authorId]);
        return $response->withJson(['status' => 'success', 'message' => 'Book-Author relationship updated successfully']);
    } catch (PDOException $e) {
        return $response->withJson(['status' => 'fail', 'message' => $e->getMessage()]);
    }
})->add('tokenMiddleware');





$app->run();
?>
