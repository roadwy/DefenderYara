
rule Backdoor_BAT_Facchom_A{
	meta:
		description = "Backdoor:BAT/Facchom.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 65 79 6c 6f 67 67 65 72 } //01 00  Keylogger
		$a_01_1 = {53 6c 6f 77 4c 6f 72 69 73 } //01 00  SlowLoris
		$a_01_2 = {53 74 6f 70 46 6c 6f 6f 64 } //01 00  StopFlood
		$a_01_3 = {53 65 6e 64 57 65 62 63 61 6d } //01 00  SendWebcam
		$a_01_4 = {73 65 6e 64 73 63 72 65 65 6e } //01 00  sendscreen
		$a_01_5 = {53 74 61 72 74 73 74 72 65 73 73 65 72 } //01 00  Startstresser
		$a_01_6 = {7c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 7c 00 } //01 00  |Chrome|
		$a_01_7 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //01 00  \Google\Chrome\User Data\Default\Login Data
		$a_01_8 = {2f 00 6e 00 65 00 77 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00 } //01 00  /newconnection.php
		$a_01_9 = {6d 00 65 00 73 00 73 00 61 00 67 00 65 00 3d 00 46 00 69 00 6c 00 65 00 55 00 70 00 6c 00 6f 00 61 00 64 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 26 00 66 00 69 00 6c 00 65 00 3d 00 } //00 00  message=FileUploadCompleted&file=
		$a_00_10 = {5d 04 00 00 76 } //1c 03 
	condition:
		any of ($a_*)
 
}