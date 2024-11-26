<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';

session_start();
$app = new \Slim\App();

// Middleware function to handle token verification via JWT
$jwtMiddleware = function (Request $request, Response $response, callable $next) {
    $authorizationHeader = $request->getHeader('Authorization');

    if ($authorizationHeader) {
        $jwtToken = str_replace('Bearer ', '', $authorizationHeader[0]);

        // Check if token has been used
        if (isset($_SESSION['used_tokens']) && in_array($jwtToken, $_SESSION['used_tokens'])) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
        }

        try {
            $decoded = JWT::decode($jwtToken, new Key('server_hack', 'HS256'));
            $request = $request->withAttribute('decoded', $decoded);
            $_SESSION['used_tokens'][] = $jwtToken; // Revoke the token after using it
        } catch (\Exception $e) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized: " . $e->getMessage()))));
        }
    } else {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token not provided"))));
    }

    return $next($request, $response);
};


// User authentication or Login
$app->post('/user/login', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username = :username AND password = :password";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':username' => $usr,
            ':password' => hash('SHA256', $pass)
        ]);
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userid" => $data['userid'])
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');
            $response->getBody()->write(json_encode(array("status" => "success", "token" => $jwt, "data" => null)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed!"))));
        }
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    return $response;
});

// CREATE NEW USER
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;


    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if username already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute([':username' => $usr]);

        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username already exists")));
            return $response->withStatus(400);
        }

        // Insert new user
        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
    return $response;
});

// VIEW USER
$app->get('/user/read', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $jwtTokenUserId = $request->getAttribute('decoded')->data->userid;

        $stmt = $conn->prepare("SELECT userid, username FROM users");
        $stmt->execute();
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($users) > 0) {
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, 
                'data' => array("userid" => $jwtTokenUserId)
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => $users)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail",  "data" => "No users found")));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);

// UPDATE A USER
$app->put('/user/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());
    $userId = trim($data->userid); 
    $newUsername = trim($data->username);
    $newPassword = trim($data->password);

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the user exists
        $checkStmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE userid = :userid");
        $checkStmt->execute([':userid' => $userId]);
        $userExists = $checkStmt->fetchColumn();

        if (!$userExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "User with ID $userId does not exist.")));
        }

        // Proceed with updating the user
        $hashedPassword = hash('SHA256', $newPassword);
        $sql = "UPDATE users SET username = :username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':username' => $newUsername,
            ':password' => $hashedPassword,
            ':userid' => $userId
        ]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userid" => $userId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "User updated successfully")));
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail",  "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);

// DELETE A USER
$app->delete('/user/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());
    $userId = $data->userid; // Get the user ID from the payload

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the user exists
        $checkStmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE userid = :userid");
        $checkStmt->execute([':userid' => $userId]);
        $userExists = $checkStmt->fetchColumn();

        if (!$userExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "User with ID $userId does not exist.")));
        }

        // Proceed with deletion if the user exists
        $stmt = $conn->prepare("DELETE FROM users WHERE userid = :userid");
        $stmt->execute([':userid' => $userId]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userid" => $userId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "User deleted successfully")));
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);




// Create a new author
$app->post('/author/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $name = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("INSERT INTO authors (name) VALUES (:name)");
        $stmt->execute([':name' => $name]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("name" => $name)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Author created successfully")));
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);

// Update author information
$app->put('/author/update', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());
    $authorId = $data->authorid; // Get the author ID from the payload
    $newName = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the author exists
        $checkStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
        $checkStmt->execute([':authorid' => $authorId]);
        $authorExists = $checkStmt->fetchColumn();

        if (!$authorExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author with ID $authorId does not exist.")));
        }

        // Proceed with the update if the author exists
        $stmt = $conn->prepare("UPDATE authors SET name = :name WHERE authorid = :authorid");
        $stmt->execute([':name' => $newName, ':authorid' => $authorId]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("authorid" => $authorId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Author updated successfully")));
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);

// Get all authors
$app->get('/author/read', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Get author ID from the query parameters
        $authorId = $request->getQueryParam('authorid');

        // Prepare the SQL query to fetch authors
        $sql = "SELECT authorid, name FROM authors";
        
        // If author ID is provided, fetch that specific author
        if (!empty($authorId)) {
            $sql .= " WHERE authorid = :authorid";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':authorid', $authorId, PDO::PARAM_INT);
        } else {
            $stmt = $conn->prepare($sql);
        }

        $stmt->execute();
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($authors) > 0) {
            // Generate a new token
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("authorCount" => count($authors))
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => $authors)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No authors found")));
        }
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);

// Delete an author
$app->delete('/author/delete', function (Request $request, Response $response) {
    $data = json_decode($request->getBody());
    $authorId = $data->authorid; // Get the author ID from the payload

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the author exists
        $checkStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
        $checkStmt->execute([':authorid' => $authorId]);
        $authorExists = $checkStmt->fetchColumn();

        if (!$authorExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author with ID $authorId does not exist.")));
        }

        // Proceed with the deletion if the author exists
        $stmt = $conn->prepare("DELETE FROM authors WHERE authorid = :authorid");
        $stmt->execute([':authorid' => $authorId]);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("authorid" => $authorId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Author deleted successfully")));
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);





// Create a new book and associate it with an author
$app->post('/book/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $title = $data->title ?? null;
    $authorId = $data->authorid ?? null;

    // Validate input
    if (empty($title) || empty($authorId)) {
        return $response->withStatus(400)->getBody()->write(json_encode(array("status" => "fail", "data" => "Title and Author ID are required")));
    }

    // Database connection setup
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the author exists
        $stmt = $conn->prepare("SELECT * FROM authors WHERE authorid = :authorid");
        $stmt->execute([':authorid' => $authorId]);

        if ($stmt->rowCount() === 0) {
            return $response->withStatus(404)->getBody()->write(json_encode(array("status" => "fail", "data" => "Author not found")));
        }

        // Proceed with inserting the new book
        $stmt = $conn->prepare("INSERT INTO books (title, authorid) VALUES (:title, :authorid)");
        $stmt->execute([':title' => $title, ':authorid' => $authorId]);

        // Get the last inserted book ID
        $bookId = $conn->lastInsertId();

        // Insert into books_authors table
        $stmt = $conn->prepare("INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)");
        $stmt->execute([':bookid' => $bookId, ':authorid' => $authorId]);

        // Generate a new token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("title" => $title, "authorid" => $authorId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withStatus(201)->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Book and Book_Author Relationship created successfully")));

    } catch (PDOException $e) {
        error_log($e->getMessage());
        return $response->withStatus(500)->getBody()->write(json_encode(array("status" => "fail", "data" => "An error occurred while creating the book")));
    }
})->add($jwtMiddleware);

// Get all books
$app->get('/book/read', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("SELECT books.title, books.bookid, authors.authorid, authors.name AS author_name 
                        FROM books 
                        JOIN books_authors ON books.bookid = books_authors.bookid 
                        JOIN authors ON books_authors.authorid = authors.authorid
                        ORDER BY books.bookid");  // Sort by bookid in ascending order

        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("message" => "read_access")
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withHeader('Content-Type', 'application/json')
                        ->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => $books)));
    } catch (PDOException $e) {
        return $response->withHeader('Content-Type', 'application/json')
                        ->write(json_encode(array("status" => "fail", "data" => $e->getMessage())));
    }
})->add($jwtMiddleware);

// Update a book and its author relationship
$app->put('/book/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $bookId = $data->bookid;
    $title = $data->title ?? null;  // Title may be provided or null
    $newAuthorId = $data->authorid ?? null;  // Author ID may be provided or null

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Start a transaction
        $conn->beginTransaction();

        // If title or author ID is provided, update the books table
        if ($title || $newAuthorId) {
            $sql = "UPDATE books SET ";
            $params = [':bookid' => $bookId];
            
            // Add title to the SQL query if provided
            if ($title) {
                $sql .= "title = :title";
                $params[':title'] = $title;
            }

            // Add authorid to the SQL query if provided
            if ($newAuthorId) {
                $sql .= $title ? ", " : ""; // Add comma if title is also updated
                $sql .= "authorid = :authorid";
                $params[':authorid'] = $newAuthorId;
            }

            $sql .= " WHERE bookid = :bookid";
            $stmt = $conn->prepare($sql);
            $stmt->execute($params);
        }

        // If a new author ID is provided, update the author relationship in the books_authors table
        if ($newAuthorId) {
            $baStmt = $conn->prepare("UPDATE books_authors SET authorid = :authorid WHERE bookid = :bookid");
            $baStmt->execute([':authorid' => $newAuthorId, ':bookid' => $bookId]);
        }

        // Commit transaction
        $conn->commit();

        // Generate a new JWT token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("bookid" => $bookId, "authorid" => $newAuthorId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withJson(array("status" => "success", "token" => $new_jwt, "data" => "Book and/or author updated successfully"));
    } catch (PDOException $e) {
        // Rollback transaction if there’s an error
        $conn->rollBack();
        return $response->withJson(array("status" => "fail", "data" => $e->getMessage()));
    }
})->add($jwtMiddleware);

// Delete a book and its relationships in books_authors
$app->delete('/book/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $bookId = $data->bookid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book exists in the database
        $checkStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookid = :bookid");
        $checkStmt->execute([':bookid' => $bookId]);
        $bookExists = $checkStmt->fetchColumn();

        if (!$bookExists) {
            return $response->withJson(array(
                "status" => "fail",
                "data" => "Book not found"
            ), 404);
        }

        // Start a transaction
        $conn->beginTransaction();

        // Delete from books_authors table first
        $stmt = $conn->prepare("DELETE FROM books_authors WHERE bookid = :bookid");
        $stmt->execute([':bookid' => $bookId]);

        // Delete the book from the books table
        $bookStmt = $conn->prepare("DELETE FROM books WHERE bookid = :bookid");
        $bookStmt->execute([':bookid' => $bookId]);

        // Commit transaction
        $conn->commit();

        // Generate a new token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("bookid" => $bookId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->withJson(array(
            "status" => "success",
            "token" => $new_jwt,
            "data" => "Book and its relationships deleted successfully"
        ));
    } catch (PDOException $e) {
        // Rollback if there’s an error
        $conn->rollBack();
        return $response->withJson(array(
            "status" => "fail",
            "data" => array("title" => $e->getMessage())
        ));
    }
})->add($jwtMiddleware);





// Create a new book-author relationship (direct to books)
$app->post('/books_authors/create', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $bookId = $data->bookid;
    $authorId = $data->authorid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book exists
        $bookStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookid = :bookid");
        $bookStmt->execute([':bookid' => $bookId]);
        $bookExists = $bookStmt->fetchColumn();

        // Check if the author exists
        $authorStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
        $authorStmt->execute([':authorid' => $authorId]);
        $authorExists = $authorStmt->fetchColumn();

        if (!$bookExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book does not exist")));
        }

        if (!$authorExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author does not exist")));
        }

        // Insert book-author relationship
        $stmt = $conn->prepare("INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)");
        $stmt->execute([':bookid' => $bookId, ':authorid' => $authorId]);

        // Generate a new token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("bookid" => $bookId, "authorid" => $authorId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Book-author relationship created successfully")));
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) {
            // Foreign key constraint violation
            return $response->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => array("title" => "Foreign key constraint violation", "details" => $e->getMessage())
            )));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    }
})->add($jwtMiddleware);

// Get all book-author relationships
$app->get('/books_authors/read', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all book-author relationships along with book and author details
        $stmt = $conn->prepare("
            SELECT ba.collectionid, ba.bookid, ba.authorid, b.title AS book_title, a.name AS author_name 
            FROM books_authors ba 
            LEFT JOIN books b ON ba.bookid = b.bookid 
            LEFT JOIN authors a ON ba.authorid = a.authorid
        ");
        $stmt->execute();
        $bookAuthors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($bookAuthors) > 0) {
            // Generate a new token
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("bookAuthorCount" => count($bookAuthors))
            ];
            $new_jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => $bookAuthors)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No book-author relationships found")));
        }
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);

// Update book-author relationship
$app->put('/books_authors/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $collectionId = $data->collectionid;
    $newBookId = $data->bookid;
    $newAuthorId = $data->authorid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the book exists
        $bookStmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE bookid = :bookid");
        $bookStmt->execute([':bookid' => $newBookId]);
        $bookExists = $bookStmt->fetchColumn();

        // Check if the author exists
        $authorStmt = $conn->prepare("SELECT COUNT(*) FROM authors WHERE authorid = :authorid");
        $authorStmt->execute([':authorid' => $newAuthorId]);
        $authorExists = $authorStmt->fetchColumn();

        if (!$bookExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book does not exist")));
        }

        if (!$authorExists) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author does not exist")));
        }

        // Update book-author relationship
        $stmt = $conn->prepare("UPDATE books_authors SET bookid = :bookid, authorid = :authorid WHERE collectionid = :collectionid");
        $stmt->execute([':bookid' => $newBookId, ':authorid' => $newAuthorId, ':collectionid' => $collectionId]);

        // Generate a new token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("collectionid" => $collectionId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Book-author relationship updated successfully")));
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) {
            // Foreign key constraint violation
            return $response->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => array("title" => "Foreign key constraint violation", "details" => $e->getMessage())
            )));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    }
})->add($jwtMiddleware);

// Delete a book-author relationship
$app->delete('/books_authors/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $collectionId = $data->collectionid;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("DELETE FROM books_authors WHERE collectionid = :collectionid");
        $stmt->execute([':collectionid' => $collectionId]);

        // Generate a new token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("collectionid" => $collectionId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $new_jwt, "data" => "Book-author relationship deleted successfully")));
    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($jwtMiddleware);


$app->run();
?>

