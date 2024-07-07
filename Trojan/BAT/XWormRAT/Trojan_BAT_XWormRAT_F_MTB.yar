
rule Trojan_BAT_XWormRAT_F_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 7e 5f 01 00 04 28 90 01 02 00 06 14 14 6f 90 01 01 00 00 0a 26 20 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}