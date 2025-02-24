
rule Trojan_Win32_ICLoader_AIC_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.AIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f8 a1 34 30 4c 00 c7 44 24 10 00 00 00 00 8d 14 09 8b 1d 20 11 4c 00 0b d0 68 9c 30 4c 00 89 54 24 10 57 df 6c 24 14 dc 05 58 30 4c 00 dd 1d 58 30 4c 00 ff d3 89 06 68 88 30 4c 00 57 ff d3 89 46 04 68 74 30 4c 00 57 ff d3 89 46 08 68 64 30 4c 00 57 ff d3 8b 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ICLoader_AIC_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.AIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 c9 10 c0 e9 03 81 e1 ff 00 00 00 89 4c 24 00 db 44 24 00 dc 3d c8 49 8a 00 dc 05 58 10 8a 00 dd 1d 38 4a 8a 00 ff 15 ?? ?? ?? ?? 25 ff 00 00 00 83 f8 06 0f 93 c2 83 f8 06 } //2
		$a_03_1 = {56 57 68 24 4b 8a 00 68 48 48 8a 00 ff 15 ?? ?? ?? ?? a1 64 10 8a 00 8b 35 f0 e2 89 00 50 ff d6 8b 3d f4 e2 89 00 68 b8 10 8a 00 50 ff d7 8b 0d 64 10 8a 00 a3 78 49 8a 00 51 ff d6 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}