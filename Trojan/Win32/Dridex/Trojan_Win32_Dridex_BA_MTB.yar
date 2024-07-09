
rule Trojan_Win32_Dridex_BA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ea 2d ad 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ba 01 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 d8 01 02 8b 45 c8 03 45 a8 2d 67 2b 00 00 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 } //1
		$a_81_1 = {74 67 6b 67 65 74 68 6a 72 6e 67 65 77 75 62 34 79 68 32 32 32 31 75 6a 6d 65 74 72 66 76 31 65 74 37 33 34 74 64 63 77 31 36 73 78 71 61 31 7a } //1 tgkgethjrngewub4yh2221ujmetrfv1et734tdcw16sxqa1z
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Dridex_BA_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.BA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 ca 89 4c 24 1c 2b c8 83 c1 25 89 4c 24 18 83 fe 09 74 1e 0f b6 c8 8a d3 6b c9 1a f6 da 2a d1 8b 4c 24 10 02 ca 89 4c 24 10 } //10
		$a_01_1 = {29 19 8d 50 29 83 e9 08 89 54 24 10 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}