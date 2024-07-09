
rule Trojan_Win32_Zenpak_DEF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a cb 0f b6 c3 2a 4c 24 34 a3 ?? ?? ?? ?? 80 c1 09 8b 3d ?? ?? ?? ?? 2a d3 0f b6 c2 6b d0 42 0f b7 c6 8b 35 ?? ?? ?? ?? 2a d3 80 c2 52 89 54 24 24 88 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}