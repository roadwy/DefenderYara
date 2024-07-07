
rule Trojan_BAT_zgRAT_Y_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 04 00 00 8d 90 01 01 00 00 01 13 01 20 90 00 } //2
		$a_03_1 = {0a 14 14 6f 90 01 01 00 00 0a 26 20 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}