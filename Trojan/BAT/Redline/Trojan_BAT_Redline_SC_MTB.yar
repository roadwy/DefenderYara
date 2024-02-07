
rule Trojan_BAT_Redline_SC_MTB{
	meta:
		description = "Trojan:BAT/Redline.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 00 8e 69 28 90 01 03 06 13 04 38 90 01 04 73 90 01 03 0a 13 03 38 90 01 04 11 04 03 28 90 01 03 06 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {54 00 35 00 41 00 41 00 5a 00 } //01 00  T5AAZ
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_4 = {46 00 61 00 62 00 72 00 61 00 6b 00 61 00 } //00 00  Fabraka
	condition:
		any of ($a_*)
 
}