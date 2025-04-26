
rule Trojan_BAT_XWormRAT_G_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 16 73 ?? ?? 00 0a 0d 09 07 6f ?? ?? 00 0a 7e ?? 00 00 04 07 6f ?? ?? 00 0a 14 6f } //2
		$a_01_1 = {20 00 01 00 00 14 14 14 6f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}