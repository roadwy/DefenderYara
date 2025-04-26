
rule Trojan_BAT_XWormRAT_V_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 8d ?? 00 00 01 fe ?? ?? 00 fe ?? ?? 00 8e 69 fe ?? ?? 00 28 ?? 00 00 0a 3b ?? 00 00 00 fe ?? ?? 00 fe ?? ?? 00 28 ?? 00 00 0a fe ?? 00 00 a2 14 fe } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}