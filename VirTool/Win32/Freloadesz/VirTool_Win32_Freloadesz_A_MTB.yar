
rule VirTool_Win32_Freloadesz_A_MTB{
	meta:
		description = "VirTool:Win32/Freloadesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 30 0a 40 3d 6e 61 40 00 ?? ?? 8b 75 d0 8b 7d cc 6a 00 68 16 01 00 00 68 58 60 40 00 56 57 ?? ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 6a 00 6a 00 57 } //1
		$a_03_1 = {8b 55 18 0f 57 c0 8b 45 14 03 d1 8b ca 66 0f d6 45 e0 48 c1 e9 02 23 c8 c7 45 e8 00 00 00 00 8b 45 10 83 e2 03 6a 1c 0f 11 45 d0 8b 04 88 ?? ?? ?? 51 6a 00 8b 04 ?? 50 89 45 c4 } //1
		$a_03_2 = {8b 45 10 83 e2 03 8b 04 88 8b 3c ?? 57 89 7d b8 ?? ?? ?? ?? ?? ?? 89 45 c8 ?? ?? ?? 50 6a 40 68 16 01 00 00 56 57 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}