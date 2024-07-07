
rule Trojan_BAT_XWormRAT_E_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 01 00 00 0a 16 6f 90 01 01 00 00 0a 13 08 12 08 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 09 11 07 12 03 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}