
rule Backdoor_BAT_DCRat_AM_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 ff a3 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 21 01 00 00 18 01 00 00 8c 04 00 00 } //01 00 
		$a_01_1 = {44 00 43 00 52 00 61 00 74 00 2e 00 43 00 6f 00 64 00 65 00 } //01 00  DCRat.Code
		$a_01_2 = {61 00 48 00 52 00 30 00 63 00 48 00 4d 00 36 00 4c 00 79 00 39 00 70 00 63 00 47 00 6c 00 75 00 5a 00 6d 00 38 00 75 00 61 00 57 00 38 00 76 00 61 00 6e 00 4e 00 76 00 62 00 67 00 } //01 00  aHR0cHM6Ly9pcGluZm8uaW8vanNvbg
		$a_01_3 = {41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 3a 00 } //00 00  Antivirus:
	condition:
		any of ($a_*)
 
}