<?php

header("Content-Type: application/json");

require_once "db.php";


/* =========================
   GET DATA FROM AJAX
========================= */

$email =
    trim($_POST["email"] ?? "");

$password =
    $_POST["password"] ?? "";


/* =========================
   VALIDATE EMAIL
========================= */

if (!filter_var(
    $email,
    FILTER_VALIDATE_EMAIL
)) {

    echo json_encode([
        "success" => false,
        "message" => "Invalid email!"
    ]);

    exit();
}


/* =========================
   CHECK PASSWORD
========================= */

if ($password === "") {

    echo json_encode([
        "success" => false,
        "message" => "Please enter password!"
    ]);

    exit();
}


/* =========================
   FIND USER
========================= */

$sql = "
    SELECT id, email, password
    FROM users
    WHERE email = ?
";


$stmt = $conn->prepare($sql);

$stmt->bind_param(
    "s",
    $email
);

$stmt->execute();

$result =
    $stmt->get_result();


/* =========================
   EMAIL NOT FOUND
========================= */

if ($result->num_rows === 0) {


    /*
       FIRST LOGIN:

       Since you want the login page
       to save the account initially,
       create the account here.
    */


    $hashedPassword =
        password_hash(
            $password,
            PASSWORD_DEFAULT
        );


    $insertSql = "
        INSERT INTO users
        (email, password)
        VALUES (?, ?)
    ";


    $insertStmt =
        $conn->prepare(
            $insertSql
        );


    $insertStmt->bind_param(
        "ss",
        $email,
        $hashedPassword
    );


    if ($insertStmt->execute()) {


        echo json_encode([

            "success" => true,

            "message" =>
                "Account created successfully!"

        ]);

    }

    else {


        echo json_encode([

            "success" => false,

            "message" =>
                "Unable to create account."

        ]);

    }


    exit();

}


/* =========================
   EXISTING USER
========================= */

$user =
    $result->fetch_assoc();


/* =========================
   CHECK PASSWORD
========================= */

if (!password_verify(
    $password,
    $user["password"]
)) {


    echo json_encode([

        "success" => false,

        "message" =>
            "Invalid password!"

    ]);

    exit();

}


/* =========================
   LOGIN SUCCESS
========================= */

echo json_encode([

    "success" => true,

    "message" =>
        "Login successful!"

]);


$stmt->close();

$conn->close();

?>