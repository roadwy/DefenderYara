
rule Trojan_BAT_Formbook_GIF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 72 07 a3 02 70 72 0b a3 02 70 6f 90 01 03 0a 0c 06 08 72 11 a3 02 70 72 ed 02 00 70 6f 90 01 03 0a 7d bf 00 00 04 16 06 7b bf 00 00 04 6f 90 01 03 0a 28 90 01 03 0a 7e c1 00 00 04 25 2d 17 26 7e c0 00 00 04 fe 06 64 00 00 06 73 78 00 00 0a 25 80 c1 00 00 04 28 90 01 03 2b 06 fe 06 61 00 00 06 73 7a 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 0d 28 90 01 03 0a 09 6f 90 01 03 0a 13 04 11 04 6f 90 01 03 0a 16 9a 6f 90 01 03 0a 18 9a 13 05 11 05 16 8c 3a 00 00 01 02 7b 0f 00 00 04 13 08 11 08 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}