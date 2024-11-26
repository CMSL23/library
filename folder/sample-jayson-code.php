<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$app = new \Slim\App;

$key = 'server_hack';  // Shared secret key for all JWTs

// Function to create JWT
function createToken($data, $key, $issuer, $audience, $expiry = 3600) {
    $iat = time();
    $payload = [
        'iss' => $issuer,
        'aud' => $audience,
        'iat' => $iat,
        'exp' => $iat + $expiry,
        'data' => $data
    ];
    return JWT::encode($payload, $key, 'HS256');
}

// Create User
$app->post('/user', function (Request $request, Response $response, array $args) use ($key) {
    $data = json_decode($request->getBody());
    $username = $data->username;
    $email = $data->email;
    $password = password_hash($data->password, PASSWORD_DEFAULT); // Hashing the password for security

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Avoid duplicate emails
        $checkDuplicate = "SELECT * FROM users WHERE email = :email";
        $stmt = $conn->prepare($checkDuplicate);
        $stmt->execute([':email' => $email]);
        if ($stmt->rowCount() > 0) {
            return $response->withJson(["status" => "fail", "message" => "Email already exists"], 409);
        }

        $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':username' => $username, ':email' => $email, ':password' => $password]);

        // Create JWT token for user
        $token = createToken(['username' => $username, 'email' => $email], $key, 'http://library.org', 'http://library.com');

        return $response->withJson(["status" => "success", "token" => $token, "data" => null], 201);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Get All Users
$app->get('/users', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "SELECT * FROM users";
        $stmt = $conn->query($sql);
        $users = $stmt->fetchAll(PDO::FETCH_OBJ);
        return $response->withJson(["status" => "success", "data" => $users], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Get a Specific User by ID
$app->get('/user/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':id' => $id]);
        $user = $stmt->fetch(PDO::FETCH_OBJ);

        if (!$user) {
            return $response->withJson(["status" => "fail", "message" => "User not found"], 404);
        }

        return $response->withJson(["status" => "success", "data" => $user], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Update User
$app->put('/user/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $data = json_decode($request->getBody());
    $username = $data->username;
    $email = $data->email;
    $password = password_hash($data->password, PASSWORD_DEFAULT); // Hashing the password for security

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Avoid duplicate emails
        $checkDuplicate = "SELECT * FROM users WHERE email = :email AND id != :id";
        $stmt = $conn->prepare($checkDuplicate);
        $stmt->execute([':email' => $email, ':id' => $id]);
        if ($stmt->rowCount() > 0) {
            return $response->withJson(["status" => "fail", "message" => "Email already exists for another user"], 409);
        }

        $sql = "UPDATE users SET username = :username, email = :email, password = :password WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':username' => $username, ':email' => $email, ':password' => $password, ':id' => $id]);

        return $response->withJson(["status" => "success", "message" => "User updated"], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Delete User
$app->delete('/user/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM users WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':id' => $id]);

        return $response->withJson(["status" => "success", "message" => "User deleted"], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});
?>

// Create Author
$app->post('/author', function (Request $request, Response $response, array $args) use ($key) {
    $data = json_decode($request->getBody());
    $authorName = $data->name;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Avoid duplicate author names
        $checkDuplicate = "SELECT * FROM authors WHERE name = :name";
        $stmt = $conn->prepare($checkDuplicate);
        $stmt->execute([':name' => $authorName]);
        if ($stmt->rowCount() > 0) {
            return $response->withJson(["status" => "fail", "message" => "Author already exists"], 409);
        }

        $sql = "INSERT INTO authors (name) VALUES (:name)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':name' => $authorName]);

        // Create JWT token for author
        $token = createToken(['name' => $authorName], $key, 'http://library.org', 'http://library.com');

        return $response->withJson(["status" => "success", "token" => $token, "data" => null], 201);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Get All Authors
$app->get('/authors', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "SELECT * FROM authors";
        $stmt = $conn->query($sql);
        $authors = $stmt->fetchAll(PDO::FETCH_OBJ);
        return $response->withJson(["status" => "success", "data" => $authors], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Update Author
$app->put('/author/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $data = json_decode($request->getBody());
    $authorName = $data->name;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE authors SET name = :name WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':name' => $authorName, ':id' => $id]);

        return $response->withJson(["status" => "success", "message" => "Author updated"], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Delete Author
$app->delete('/author/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM authors WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':id' => $id]);

        return $response->withJson(["status" => "success", "message" => "Author deleted"], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Create Book
$app->post('/book', function (Request $request, Response $response, array $args) use ($key) {
    $data = json_decode($request->getBody());
    $bookTitle = $data->title;
    $authorId = $data->authorid;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Avoid duplicate book titles
        $checkDuplicate = "SELECT * FROM books WHERE title = :title AND authorid = :authorid";
        $stmt = $conn->prepare($checkDuplicate);
        $stmt->execute([':title' => $bookTitle, ':authorid' => $authorId]);
        if ($stmt->rowCount() > 0) {
            return $response->withJson(["status" => "fail", "message" => "Book already exists"], 409);
        }

        $sql = "INSERT INTO books (title, authorid) VALUES (:title, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':title' => $bookTitle, ':authorid' => $authorId]);

        // Create JWT token for book
        $token = createToken(['title' => $bookTitle, 'authorid' => $authorId], $key, 'http://library.org', 'http://library.com');

        return $response->withJson(["status" => "success", "token" => $token, "data" => null], 201);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Get All Books
$app->get('/books', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "SELECT * FROM books";
        $stmt = $conn->query($sql);
        $books = $stmt->fetchAll(PDO::FETCH_OBJ);
        return $response->withJson(["status" => "success", "data" => $books], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Update Book
$app->put('/book/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $data = json_decode($request->getBody());
    $bookTitle = $data->title;
    $authorId = $data->authorid;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET title = :title, authorid = :authorid WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':title' => $bookTitle, ':authorid' => $authorId, ':id' => $id]);

        return $response->withJson(["status" => "success", "message" => "Book updated"], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

// Delete Book
$app->delete('/book/{id}', function (Request $request, Response $response, array $args) {
    $id = $args['id'];
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library2";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':id' => $id]);

        return $response->withJson(["status" => "success", "message" => "Book deleted"], 200);
    } catch (PDOException $e) {
        return $response->withJson(["status" => "fail", "message" => $e->getMessage()], 500);
    }
});

$app->run();
?>
