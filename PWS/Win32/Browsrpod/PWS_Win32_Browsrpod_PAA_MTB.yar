
rule PWS_Win32_Browsrpod_PAA_MTB{
	meta:
		description = "PWS:Win32/Browsrpod.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {61 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 74 00 61 00 67 00 20 00 6d 00 69 00 73 00 6d 00 61 00 74 00 63 00 68 00 } //0a 00  authentication tag mismatch
		$a_01_1 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //0a 00  password_value
		$a_01_2 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 74 00 78 00 74 00 } //0a 00  Passwords.txt
		$a_01_3 = {5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //0a 00  \Login Data
		$a_01_4 = {54 00 6f 00 6b 00 65 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //0a 00  Tokens.txt
		$a_01_5 = {49 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //00 00  Info.txt
	condition:
		any of ($a_*)
 
}