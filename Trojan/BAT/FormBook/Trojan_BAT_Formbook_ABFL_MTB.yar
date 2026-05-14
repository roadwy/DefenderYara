
rule Trojan_BAT_Formbook_ABFL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ABFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 7d 93 00 00 04 06 03 7d 92 00 00 04 16 02 7b 8e 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 06 fe 06 76 00 00 06 73 1a 00 00 0a 28 ?? 00 00 2b 2a } //5
		$a_03_1 = {0a 06 03 7d ?? 00 00 04 19 8d ?? 00 00 01 25 16 1f 10 9e 25 17 1e 9e 06 } //4
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4+(#a_80_2  & 1)*1) >=10
 
}