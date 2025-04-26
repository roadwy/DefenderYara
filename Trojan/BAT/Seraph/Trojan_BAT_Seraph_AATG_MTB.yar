
rule Trojan_BAT_Seraph_AATG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 73 26 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 1e 2c 06 2b 0f 2b 11 2b 12 16 2d f4 2b 14 2b 15 2b 1a de 42 11 04 2b ed 08 2b ec 6f 29 00 00 0a 2b e7 08 2b e9 6f ?? 00 00 0a 2b e4 13 05 2b e2 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}