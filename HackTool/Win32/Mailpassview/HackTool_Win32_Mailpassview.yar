
rule HackTool_Win32_Mailpassview{
	meta:
		description = "HackTool:Win32/Mailpassview,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 46 00 6f 00 78 00 2e 00 65 00 78 00 65 00 } //05 00  PasswordFox.exe
		$a_01_1 = {56 00 4e 00 43 00 50 00 61 00 73 00 73 00 56 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //05 00  VNCPassView.exe
		$a_01_2 = {42 00 75 00 6c 00 6c 00 65 00 74 00 73 00 50 00 61 00 73 00 73 00 56 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //01 00  BulletsPassView.exe
		$a_01_3 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 46 00 69 00 65 00 6c 00 64 00 } //01 00  Password Field
		$a_01_4 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 54 00 79 00 70 00 65 00 } //01 00  Password Type
		$a_01_5 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 20 00 4c 00 69 00 73 00 74 00 } //00 00  Passwords List
		$a_00_6 = {78 25 01 00 17 00 } //17 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win32_Mailpassview_2{
	meta:
		description = "HackTool:Win32/Mailpassview,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6c 70 76 2e 70 64 62 } //0a 00  mailpv.pdb
		$a_01_1 = {77 77 77 2e 6e 69 72 73 6f 66 74 2e 6e 65 74 } //01 00  www.nirsoft.net
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 4f 75 74 6c 6f 6f 6b 5c 4f 4d 49 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //01 00  Software\Microsoft\Office\Outlook\OMI Account Manager\Accounts
		$a_01_3 = {50 61 73 73 77 6f 72 64 2e 4e 45 54 20 4d 65 73 73 65 6e 67 65 72 20 53 65 72 76 69 63 65 } //01 00  Password.NET Messenger Service
		$a_01_4 = {53 45 4c 45 43 54 20 69 64 2c 20 68 6f 73 74 6e 61 6d 65 2c 20 68 74 74 70 52 65 61 6c 6d 2c 20 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c 2c 20 75 73 65 72 6e 61 6d 65 46 69 65 6c 64 2c 20 70 61 73 73 77 6f 72 64 46 69 65 6c 64 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 } //01 00  SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPass
		$a_01_5 = {4b 00 65 00 65 00 50 00 61 00 73 00 73 00 20 00 63 00 73 00 76 00 20 00 66 00 69 00 6c 00 65 00 } //00 00  KeePass csv file
		$a_00_6 = {80 10 00 00 0b f3 5a 03 a8 7e 2c de } //41 39 
	condition:
		any of ($a_*)
 
}