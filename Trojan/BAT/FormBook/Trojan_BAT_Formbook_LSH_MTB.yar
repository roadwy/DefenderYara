
rule Trojan_BAT_Formbook_LSH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.LSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 09 16 0c 2b 61 09 07 08 6f 90 01 03 0a 13 04 11 04 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 13 0a 11 0a 2c 3d 06 12 04 28 90 01 03 0a 6f 90 01 03 0a 06 12 04 28 90 01 03 0a 6f 90 01 03 0a 06 11 04 8c 90 01 03 01 20 90 01 03 f0 28 90 01 03 06 18 14 28 90 01 03 0a a5 09 00 00 01 6f 90 01 03 0a 08 17 d6 0c 08 11 09 fe 02 16 fe 01 13 0b 11 0b 2d 91 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}