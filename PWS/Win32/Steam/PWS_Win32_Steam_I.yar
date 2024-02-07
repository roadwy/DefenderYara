
rule PWS_Win32_Steam_I{
	meta:
		description = "PWS:Win32/Steam.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 00 53 74 65 61 6d 2e 65 78 65 00 } //01 00 
		$a_01_1 = {53 74 65 61 6d 20 41 63 63 6f 75 6e 74 20 48 61 63 6b 65 72 } //01 00  Steam Account Hacker
		$a_01_2 = {53 00 74 00 65 00 61 00 6d 00 20 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 3a 00 20 00 53 00 74 00 65 00 61 00 6d 00 20 00 4c 00 6f 00 67 00 69 00 6e 00 } //01 00  Steam Stealer : Steam Login
		$a_01_3 = {53 00 74 00 65 00 61 00 6d 00 20 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 3a 00 20 00 45 00 6d 00 61 00 69 00 6c 00 20 00 6c 00 6f 00 67 00 69 00 6e 00 } //00 00  Steam Stealer : Email login
	condition:
		any of ($a_*)
 
}