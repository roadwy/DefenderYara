
rule Trojan_BAT_XWormRAT_X_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 d4 91 11 04 11 04 07 95 11 04 08 95 58 20 90 01 04 5f 95 61 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}