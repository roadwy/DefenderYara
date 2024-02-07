
rule Backdoor_Win32_DialPlatform_B{
	meta:
		description = "Backdoor:Win32/DialPlatform.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 7e 31 5c 69 6e 74 65 72 6e 7e 31 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 25 31 } //02 00  c:\progra~1\intern~1\iexplore.exe %1
		$a_01_1 = {3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 4d 65 6d 62 65 72 73 20 41 72 65 61 20 41 63 63 65 73 73 3c 2f 74 69 74 6c 65 3e 3c 2f 68 65 61 64 3e } //03 00  <head><title>Members Area Access</title></head>
		$a_01_2 = {53 61 76 65 20 74 68 65 20 6c 6f 67 69 6e 20 61 6e 64 20 70 61 73 73 77 6f 72 64 20 67 65 6e 65 72 61 74 65 64 20 66 6f 72 20 79 6f 75 2e 20 49 74 20 77 69 6c 6c 20 67 72 61 6e 74 20 61 63 63 65 73 73 20 66 6f 72 20 37 20 64 61 79 73 2e } //03 00  Save the login and password generated for you. It will grant access for 7 days.
		$a_01_3 = {3c 62 72 3e 54 6f 20 61 63 63 65 73 73 20 75 73 65 20 79 6f 75 72 20 75 73 75 61 6c 20 63 6f 6e 6e 65 63 74 69 6f 6e 2e } //01 00  <br>To access use your usual connection.
		$a_01_4 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 43 6c 61 73 73 5c 7b 34 44 33 36 45 39 36 44 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d } //00 00  System\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}
	condition:
		any of ($a_*)
 
}