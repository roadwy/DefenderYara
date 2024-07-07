
rule Trojan_BAT_XWormRAT_V_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 8d 90 01 01 00 00 01 fe 90 01 02 00 fe 90 01 02 00 8e 69 fe 90 01 02 00 28 90 01 01 00 00 0a 3b 90 01 01 00 00 00 fe 90 01 02 00 fe 90 01 02 00 28 90 01 01 00 00 0a fe 90 01 01 00 00 a2 14 fe 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}