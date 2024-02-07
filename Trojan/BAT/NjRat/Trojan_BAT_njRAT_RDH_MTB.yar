
rule Trojan_BAT_njRAT_RDH_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 06 18 58 93 1f 10 62 08 58 0c 1d 13 09 1e } //02 00 
		$a_01_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0f } //01 00 
		$a_01_2 = {6b 65 72 6e 65 6c 33 32 } //01 00  kernel32
		$a_01_3 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_5 = {50 61 73 73 77 6f 72 64 44 65 72 69 76 65 42 79 74 65 73 } //01 00  PasswordDeriveBytes
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}