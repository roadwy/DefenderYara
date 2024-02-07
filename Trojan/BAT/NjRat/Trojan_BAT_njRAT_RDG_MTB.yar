
rule Trojan_BAT_njRAT_RDG_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 06 18 58 93 1f 10 62 08 58 0c 1e } //01 00 
		$a_01_1 = {6b 65 72 6e 65 6c 33 32 } //01 00  kernel32
		$a_01_2 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_4 = {50 61 73 73 77 6f 72 64 44 65 72 69 76 65 42 79 74 65 73 } //01 00  PasswordDeriveBytes
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}