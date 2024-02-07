
rule Trojan_BAT_FormBook_EWU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 35 61 39 65 35 33 66 35 2d 64 66 63 65 2d 34 32 30 64 2d 39 65 65 62 2d 31 37 64 61 64 38 39 32 38 33 65 30 } //01 00  $5a9e53f5-dfce-420d-9eeb-17dad89283e0
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  MD5CryptoServiceProvider
	condition:
		any of ($a_*)
 
}