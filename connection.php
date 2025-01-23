<?php

$con=mysqli_connect("localhost","root","","testinf");

if(mysqli_connect_error())
{
    echo "<script>alert('cannot connect to database');</script>";
    exit();
}


?>