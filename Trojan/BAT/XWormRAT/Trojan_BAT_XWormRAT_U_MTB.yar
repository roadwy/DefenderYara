
rule Trojan_BAT_XWormRAT_U_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 02 1a 58 11 04 16 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 7e ?? ?? 00 04 11 05 6f ?? 00 00 0a 7e ?? ?? 00 04 02 6f ?? 00 00 0a 7e ?? ?? 00 04 6f ?? 00 00 0a 17 59 28 ?? 00 00 0a 16 7e ?? ?? 00 04 02 1a 28 ?? 00 00 0a 11 05 } //2
		$a_01_1 = {57 bd a3 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 d3 00 00 00 fa 00 00 00 9f 04 00 00 f2 09 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}