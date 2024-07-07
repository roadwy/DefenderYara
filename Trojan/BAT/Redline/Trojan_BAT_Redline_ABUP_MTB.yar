
rule Trojan_BAT_Redline_ABUP_MTB{
	meta:
		description = "Trojan:BAT/Redline.ABUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 91 0b 7e 90 01 01 00 00 04 06 7e 90 01 01 00 00 04 06 7e 90 01 01 00 00 04 5d 91 07 61 b4 9c 06 17 d6 0a 00 06 7e 90 01 01 00 00 04 17 da fe 01 16 fe 01 13 06 11 06 2d 89 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}