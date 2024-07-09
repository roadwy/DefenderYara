
rule Trojan_Win32_Dridex_AA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 16 03 f8 0f b7 c1 03 d8 89 1d ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 2b eb 81 fd 6a 02 00 00 } //10
		$a_02_1 = {8d 4c 28 01 81 c2 cc bc 05 01 0f b7 c9 89 16 89 15 ?? ?? ?? ?? 0f b7 d1 8d 84 00 e8 3b 00 00 2b c2 03 c7 83 c6 04 83 6c 24 10 01 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 8a 24 0a 34 ff 00 c4 88 24 0e 5e 5d c3 } //1
		$a_02_1 = {8b 4d e8 8b 55 ec 8a 5d e7 32 5d de 29 d0 8b 55 b4 88 1c 0a 8b 4d d8 03 45 e8 89 4d c8 89 45 c4 8b 4d c0 89 4d d0 8b 4d bc 39 c8 0f 84 ?? ?? 00 00 e9 ?? ?? 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Dridex_AA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 8a f2 66 3b c6 74 24 0f b7 01 0f af d8 8a d3 2a 54 24 10 80 ea 35 0f b6 c2 8a f2 66 3b c7 74 0b } //10
		$a_01_1 = {0f b6 c1 66 3b c7 74 26 0f b7 02 0f af d8 8a cb 2a 4c 24 10 80 e9 35 0f b6 c1 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}