
rule Trojan_Win32_VBKrypt_AM_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {78 61 6d 70 70 5f 73 74 61 72 74 } //03 00  xampp_start
		$a_81_1 = {50 6f 6c 79 63 79 73 74 69 63 } //03 00  Polycystic
		$a_81_2 = {47 6f 6f 70 79 } //03 00  Goopy
		$a_81_3 = {44 61 73 63 68 61 67 67 61 } //03 00  Daschagga
		$a_81_4 = {6d 69 6e 74 6d 61 73 74 65 72 37 2e 64 6c 6c } //03 00  mintmaster7.dll
		$a_81_5 = {43 6f 6c 6f 70 65 78 6f 74 6f 6d 79 } //03 00  Colopexotomy
		$a_81_6 = {56 42 2e 54 69 6d 65 72 } //00 00  VB.Timer
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VBKrypt_AM_MTB_2{
	meta:
		description = "Trojan:Win32/VBKrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 49 53 54 41 4e 43 45 } //01 00  DISTANCE
		$a_01_1 = {41 63 63 75 73 61 74 69 76 65 73 38 } //01 00  Accusatives8
		$a_01_2 = {64 65 6d 6f 6e 73 74 72 61 6e 74 65 72 6e 65 } //01 00  demonstranterne
		$a_01_3 = {48 00 43 00 68 00 65 00 58 00 4c 00 6a 00 54 00 57 00 62 00 62 00 61 00 4a 00 64 00 38 00 6d 00 64 00 49 00 36 00 33 00 } //01 00  HCheXLjTWbbaJd8mdI63
		$a_01_4 = {49 00 30 00 66 00 46 00 43 00 59 00 75 00 4c 00 37 00 6e 00 4f 00 6a 00 34 00 55 00 68 00 59 00 37 00 5a 00 45 00 6a 00 34 00 74 00 70 00 43 00 45 00 77 00 38 00 } //00 00  I0fFCYuL7nOj4UhY7ZEj4tpCEw8
	condition:
		any of ($a_*)
 
}