
rule Trojan_BAT_XWormRAT_J_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 91 20 90 01 02 00 00 28 90 01 02 00 06 11 04 20 90 01 02 00 00 28 90 01 02 00 06 28 90 01 02 00 0a 5d 28 90 01 02 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 16 2d 90 01 01 08 8e 69 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}