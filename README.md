# Library Management System API

## Description

The **Library Management System API** is a RESTful service designed to manage libraries efficiently. It allows administrators to manage users, authors, and books. This API ensures a smooth library operation with secure authentication and robust features for scalability and reliability.

---

## Table of Contents

- [Features](#features)
- [Technology Used](#technology-used)
- [Endpoints Overview](#endpoints-overview)
- [Breakdown](#breakdown)

---

## Features

- **User Management**
  - User registration, login, and profile management.
  - Role-based access control
  
- **Author Management**
  - CRUD operations for authors.

- **Book Management**
  - CRUD operations for books.
  - Check book availability.

- **Books and Authors Relationship**
  - Endpoints to link books with their respective authors and retrieve details.
 
- **Authentication**
  - Secure JWT-based authentication

---

## Technology Used

- **Backend Framework:** Slim Framework
- **Database:** MySQL or any relational database supported by PHP
- **Development Environment:** XAMPP
- **Programming Language:** PHP 
- **Authentication:** JWT (JSON Web Token)

---

## Endpoints Overview

| **Endpoint**          | **Method** | **Description**                          |
|-----------------------|------------|------------------------------------------|
|**User Endpoint**|
| `/user/login`         | `POST`     | Authenticate user and return JWT.        |
| `/user/register`     | `POST`     | Register a new user.                     |
| `/user/read`         | `GET`      | Retrieve all registered users.           |
| `/user/update`        | `PUT`      | Update user details.                     |
| `/user/delete`       | `DELETE`   | Delete a user.                           |
|**Author Endpoint**|
| `/author/add`         | `POST`     | Add a new author.                        |
| `/author/read`       | `GET`      | Retrieve all authors.                    |
| `/author/update`      | `PUT`      | Update author details.                   |
| `/author/delete`      | `DELETE`   | Delete an author.                        |
|**Book Endpoint**|
| `/book/add`           | `POST`     | Add a new book.                          |
| `/book/read`         | `GET`      | Retrieve all books.                      |
| `/book/update`        | `PUT`      | Update book details.                     |
| `/book/delete`        | `DELETE`   | Delete a book.                           |
|**Book and Author Endpoint**|
| `/books_authors/add`    | `POST`     | Associate a book with an author.         |
| `/books_authors/read`  | `GET`      | Retrieve all book-author relationships.  |
| `/books_authors/update` | `PUT`      | Update book-author relationship.         |
| `/books_authors/delete`| `DELETE`   | Delete a book-author relationship.       |

---

## Breakdown
### User Endpoints
---
### User Register
- **Endpoint:** `/user/register`  

- **Method:** `POST`  

- **Description:** 
    Creates new user account.

- **Sample Request (JSON):**
    ```json
    {
        "username": "user",
        "password": "password"
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "data": null
        }
        ```

    - **If user already exist:**
        ```json
        {
            "status": "fail",
            "data": "Username already exists"
        }
        ```
---
### User Login
- **Endpoint:** `/user/login`  

- **Method:** `POST`  

- **Description:** 
    Authenticate a user and return a token for access.

- **Sample Request (JSON):**
    ```json
    {
        "username": "user",
        "password": "password"
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": null
        }
        ```

    - **Failure (Authentication Failed):**
        ```json
        {
            "status": "fail",
            "data": "Authentication Failed!"
        }
        ```
---
### User Read
- **Endpoint:** `/user/read`  
- **Method:** `GET`  
- **Description:**  
Retrieve details of the logged-in user.

- **Sample Request:**
    - No request body is required. Authentication is handled via the Authorization header.

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": [
                {
                    "userid": 1,
                    "username": "user"
                },
                {
                    "userid": 2,
                    "username": "user2"
                }
            ]
        }
        ```
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```

    - **Failure (No Users Found):**
        ```json
        {
            "status": "fail",
            "data": "No users found"
        }
        ```
---
### User Update
- **Endpoint:** `/user/update`  
- **Method:** `PUT`  
- **Description:**  
Update the logged-in user's profile.

- **Request Body (JSON):**
    ```json
    {
        "userid": "1",
        "username": "user123", (updated username)
        "password": "password"
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "User updated successfully"
        }
        ```

    - **Failure (User Not Found):**
        ```json
        {
            "status": "fail",
            "data": "User with ID 1 does not exist."
        }
        ```
---
### User Delete
- **Endpoint:** `/user/delete`  
- **Method:** `DELETE`  
- **Description:**  
Remove the logged-in user's account.

- **Request Body (JSON):**
    ```json
    {
        "userid": "1",
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "User deleted successfully"
        }
        ```

    - **Failure (User Not Found):**
        ```json
        {
            "status": "fail",
            "data": "User with ID 1 does not exist."
        }
        ```
---
### Author Endpoints
---
### Author Register
- **Endpoint:** `/author/register`  

- **Method:** `POST`  

- **Description:** 
    Add a new author to the database.

- **Sample Request (JSON):**
    ```json
    {
        "name": "J.K Rowling"
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": null
        }
        ```

    - **If user already exist:**
        ```json
        {
            "status": "fail",
            "data": "Author already exists"
        }
        ```
        
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Author Read
- **Endpoint:** `/author/read`  
- **Method:** `GET`  
- **Description:**  
Fetch details of all authors

- **Sample Request:**
    - No request body is required. Authentication is handled via the Authorization header.

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": [
                {
                    "authorid": 1,
                    "name": "J.K Rowling"
                },
                {
                    "authorid": 2,
                    "name": "Agatha Christie"
                }
            ]
        }
        ```
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```

    - **Failure (No Users Found):**
        ```json
        {
            "status": "fail",
            "data": "No authors found"
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Author Update
- **Endpoint:** `/author/update`  
- **Method:** `PUT`  
- **Description:**  
Update an author’s information.

- **Request Body (JSON):**
    ```json
    {
        "authorid": "1",
        "name": "JK ROWLING" (updated author name)
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Author updated successfully"
        }
        ```

    - **Failure (Author Not Found):**
        ```json
        {
            "status": "fail",
            "data": "User with ID 1 does not exist."
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Author Delete
- **Endpoint:** `/author/delete`  
- **Method:** `DELETE`  
- **Description:**  
Delete an author from the database.

- **Request Body (JSON):**
    ```json
    {
        "userid": "1",
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "User deleted successfully"
        }
        ```

    - **Failure (User Not Found):**
        ```json
        {
            "status": "fail",
            "data": "User with ID 1 does not exist."
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book Endpoints
---
### Book Register
- **Endpoint:** `/book/register`  
- **Method:** `POST`  
- **Description:**  
 Add a new book and also added to Books_Authors relationship to the database.
 
- **Request Body (JSON):**
    ```json
    {
        "title": "Harry Potter",
        "authorid": 1
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Book and Book_Author Relationship created successfully"
        }
        ```

    - **Failure (Title or Author ID not added):**
        ```json
        {
            "status": "fail",
            "data": "Title and Author ID are required"
        }
        ```
    - **Failure (Author doesnt exist):**
        ```json
        {
            "status": "fail",
            "data": "Author not found"
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book Read
- **Endpoint:** `/book/read`  
- **Method:** `GET`
- **Description:**  
Fetch details of all books

- **Sample Request:**
    - No request body is required. Authentication is handled via the Authorization header.

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": [
                {
                    "title": "Harry Potter",
                    "bookid": "1",
                    "authorid": "1",
                    "author_name": "JK ROWLING"
                }
            ]
        }
        ```
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book Update
- **Endpoint:** `/book/update`  
- **Method:** `PUT`  
- **Description:**  
Update an book's information.

- **Sample Request: - Author and Title can be updated individually**
    ```json
    {
        "bookid": "1",
        "title": "HARRY POTTER",  (updated book title)
        "authorid": 2 (updated author)
    }
    ```
    
- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Book and/or author updated successfully"
        }
        ```
        
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book Delete
- **Endpoint:** `/book/delete`  
- **Method:** `DELETE`  
- **Description:**  
Delete a book from the database.

- **Request Body (JSON):**
    ```json
    {
        "bookid": "1",
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Book and its relationships deleted successfully"
        }
        ```

    - **Failure (Book Not Found):**
        ```json
        {
            "status": "fail",
            "data": "Book not found"
        }
        ```
        
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book And Author Relationship Endpoints
---
### Book_Author Register
- **Endpoint:** `/books_authors/create`  
- **Method:** `POST`  
- **Description:**  
Creates a new book-author relationship by linking a specific book and author based on bookid and authorid.
 
- **Request Body (JSON):**
    ```json
    {
        "bookid": 1,
        "authorid": 1
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Book-author relationship created successfully"
        }
        ```

    - **Failure (Book not found in the database):**
        ```json
        {
            "status": "fail",
            "data": "Book not found"
        }
        ```
        
     - **Failure (Author not found in the database):**
        ```json
        {
            "status": "fail",
            "data": "Author not found"
        }
        ```
        
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book_Author Read
- **Endpoint:** `/book/read`  
- **Method:** `GET`
- **Description:**  
Fetch details of all books_authors

- **Sample Request:**
    - No request body is required. Authentication is handled via the Authorization header.

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": [
                {
                    "collectionid": "1",
                    "bookid": "1",
                    "authorid": "1",
                    "book_title": "HARRY POTTER",
                    "author_name": "JK ROWLING"
                }
            ]
        }
        ```
    - **Failure (No relationship found):**
        ```json
        {
            "status": "fail",
            "data": "No book-author relationships found"
        }
        ```
        
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book_Author Update
- **Endpoint:** `/books_authors/update`  
- **Method:** `PUT`  
- **Description:**  
Update an books_authors information.

- **Sample Request: - Author and Title can be updated individually**
    ```json
    {
        "collectionid": 1,
        "bookid": 2,  (updated bookid)
        "authorid": 2
    }
    ```
    
- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Book-author relationship updated successfully"
        }
        ```
        
    - **Failure (Book not found in the database):**
        ```json
        {
            "status": "fail",
            "data": "Book does not exist"
        }
        ```
        
    - **Failure (Author not found in the database):**
        ```json
        {
            "status": "fail",
            "data": "Author does not exist"
        }
        ```
        
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```
        
    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
---
### Book_Author Delete
- **Endpoint:** `/books_authors/delete`  
- **Method:** `DELETE`  
- **Description:**  
Delete a book from the database.

- **Request Body (JSON):**
    ```json
    {
        "collectionid": "1",
    }
    ```

- **Response:**
    - **Success:**
        ```json
        {
            "status": "success",
            "token": "<access_token>",
            "data": "Book-author relationship deleted successfully"
        }
        ```
        
    - **Failure (Unauthorized):**
        ```json
        {
            "status": "fail",
            "data": "Unauthorized: Token not provided"
        }
        ```

    - **Failure (Token used):**
        ```json
        {
            "status": "fail",
            "data": "Token has already been used"
        }
        ```
