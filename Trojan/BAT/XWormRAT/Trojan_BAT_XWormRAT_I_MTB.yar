
rule Trojan_BAT_XWormRAT_I_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 13 04 1b 0d 2b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}