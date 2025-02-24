
rule Trojan_BAT_Formbook_NOS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 2d 0a 04 1f 41 fe 04 16 fe 01 2b 01 17 0b } //2
		$a_01_1 = {25 17 6f 33 01 00 0a 0b 03 17 da 0d 18 13 04 } //1
		$a_03_2 = {1f 7c 07 1b 5d 17 d6 ?? ?? 00 00 0a ?? ?? 00 00 0a 07 18 d6 0b 07 06 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}