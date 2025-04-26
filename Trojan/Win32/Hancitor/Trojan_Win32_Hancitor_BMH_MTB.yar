
rule Trojan_Win32_Hancitor_BMH_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.BMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 06 2a d3 c0 e6 02 83 c1 63 2a f3 89 0d ?? ?? ?? ?? 80 c2 48 88 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? 0f b6 da 2b d9 89 06 33 c9 a3 ?? ?? ?? ?? 83 c3 63 89 0d ?? ?? ?? ?? 83 c6 04 ff 4c 24 14 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}