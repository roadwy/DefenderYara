
rule Trojan_Win32_RelineStealer_BXF_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.BXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 4d f8 2b f0 8b d6 d3 ea 89 75 9c 89 55 fc 8b 45 88 01 45 fc 8b 45 9c c1 e6 04 } //10
		$a_02_1 = {dc c0 69 54 c7 45 ?? 98 c3 e4 01 c7 85 ?? ?? ?? ?? be 14 4a 0a c7 85 ?? ?? ?? ?? 32 f5 41 2a c7 85 ?? ?? ?? ?? 52 89 eb 0e c7 85 ?? ?? ?? ?? fc 7d 9a 60 c7 85 ?? ?? ?? ?? e5 9a 40 22 c7 85 ?? ?? ?? ?? 95 54 fe 1a c7 45 ?? 87 64 58 7c c7 85 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}