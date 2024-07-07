
rule Trojan_BAT_Redline_GEB_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0f 18 9a 28 90 01 03 0a 16 8d 90 01 04 6f 90 01 03 0a a2 14 14 16 17 28 90 01 03 0a 00 00 00 00 00 06 16 5a 0a 2b 00 00 00 06 16 fe 03 13 15 11 15 3a 90 00 } //10
		$a_80_1 = {69 2e 69 62 62 2e 63 6f 2f 44 57 59 37 37 4a 33 2f } //i.ibb.co/DWY77J3/  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}