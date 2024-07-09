
rule Trojan_BAT_Redline_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2d 02 07 6f 27 00 00 0a 03 07 03 6f 4d 00 00 0a 5d 6f 27 00 00 0a 61 0c 06 72 ?? ?? 00 70 08 28 3a 01 00 0a 6f 3b 01 00 0a 26 07 17 58 0b 07 02 } //10
		$a_01_1 = {0a de 19 02 28 84 00 00 06 03 28 83 00 00 06 28 84 00 00 06 0a de 05 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}