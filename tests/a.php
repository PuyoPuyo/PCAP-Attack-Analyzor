<?php
if(empty($_FILES['pcapfile']['name'])){ // $_FILES An associative array of items uploaded to the current script via the HTTP POST method. 
	echo "Error: No file picked for uploading";
	exit();
}

	$fileName = $_FILES['pcapfile']["name"];
	$fileTmpLoc = $_FILES['pcapfile']["tmp_name"]; // File in the PHP tmp folder
	$fileType = $_FILES['pcapfile']["type"]; // What type of file is uploaded
	$fileSize = $_FILES['pcapfile']["size"]; // Size of the file

	echo shell_exec ("/usr/bin/python /tmp/lol.py");
?>
