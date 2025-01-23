<?php 
require('connection.php');

if (isset($_POST['login'])) {
    $username = mysqli_real_escape_string($con, $_POST['username']);
    $password = $_POST['password'];

    // Check if the username exists using prepared statements
    $user_query = "SELECT * FROM `registered_users` WHERE `username` = ?";
    if ($stmt = mysqli_prepare($con, $user_query)) {
        mysqli_stmt_bind_param($stmt, 's', $username);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if ($result && mysqli_num_rows($result) > 0) {
            $user = mysqli_fetch_assoc($result);
            
            // Verify the password
            if (password_verify($password, $user['password'])) {
                // Start the session and save the user data in session variables
                session_start();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['full_name'] = $user['full_name'];

                echo "<script>
                    alert('Login successful!');
                    window.location.href = 'dashboard.php'; // Redirect to a user dashboard or homepage
                </script>";
            } else {
                echo "<script>
                    alert('Incorrect password!');
                    window.location.href = 'index.php'; // Redirect to login page
                </script>";
            }
        } else {
            echo "<script>
                alert('Username does not exist!');
                window.location.href = 'index.php'; // Redirect to login page
            </script>";
        }

        mysqli_stmt_close($stmt);
    } else {
        echo "<script>
            alert('Could not execute query.');
            window.location.href = 'index.php'; // Redirect to login page
        </script>";
    }
} elseif (isset($_POST['register'])) {
    $full_name = mysqli_real_escape_string($con, $_POST['full_name']);
    $username = mysqli_real_escape_string($con, $_POST['username']);
    $email = mysqli_real_escape_string($con, $_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT); // Hash the password for security

    // Validate inputs (add more validations as needed)
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>
            alert('Invalid email format.');
            window.location.href = 'index.php';
        </script>";
        exit();
    }

    // Check if username or email already exists using prepared statements
    $user_exist_query = "SELECT * FROM `registered_users` WHERE `username` = ? OR `email` = ?";
    if ($stmt = mysqli_prepare($con, $user_exist_query)) {
        mysqli_stmt_bind_param($stmt, 'ss', $username, $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if ($result && mysqli_num_rows($result) > 0) {
            $result_fetch = mysqli_fetch_assoc($result);

            // Check which field is conflicting
            if ($result_fetch['username'] === $username) {
                echo "<script>
                    alert('Username \"$username\" is already taken.');
                    window.location.href = 'index.php';
                </script>";
            } elseif ($result_fetch['email'] === $email) {
                echo "<script>
                    alert('Email \"$email\" is already registered.');
                    window.location.href = 'index.php';
                </script>";
            }
        } else {
            // Insert the new user into the database using prepared statements
            $insert_query = "INSERT INTO `registered_users` (`full_name`, `username`, `email`, `password`) VALUES (?, ?, ?, ?)";
            if ($stmt = mysqli_prepare($con, $insert_query)) {
                mysqli_stmt_bind_param($stmt, 'ssss', $full_name, $username, $email, $password);
                if (mysqli_stmt_execute($stmt)) {
                    echo "<script>
                        alert('Registration successful!');
                        window.location.href = 'index.php';
                    </script>";
                } else {
                    echo "<script>
                        alert('Could not register user. Please try again.');
                        window.location.href = 'index.php';
                    </script>";
                }
            } else {
                echo "<script>
                    alert('Could not prepare statement.');
                    window.location.href = 'index.php';
                </script>";
            }
        }

        mysqli_stmt_close($stmt);
    } else {
        echo "<script>
            alert('Cannot run query.');
            window.location.href = 'index.php';
        </script>";
    }
} else {
    echo "<script>
        alert('Invalid request.');
        window.location.href = 'index.php'; // Redirect to login page
    </script>";
}
?>
