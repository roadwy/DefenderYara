
rule VirTool_Win32_Injector_EU{
	meta:
		description = "VirTool:Win32/Injector.EU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 45 d0 00 00 00 00 eb ?? 0f be 4d ff 83 e9 3d 89 4d d0 8a 55 d0 88 55 ff e9 ?? ?? ?? ?? 0f be 45 ff 85 c0 74 ?? 8b 4d e0 83 c1 01 89 4d e0 0f be 55 ff 83 ea 01 } //1
		$a_03_1 = {0f b6 55 fd 0f b6 45 ff 33 c2 88 45 ff 8b 4d f8 8a 55 ff 88 91 04 00 ?? ?? e9 } //1
		$a_03_2 = {55 89 e5 8b 45 08 8b 4d 0c 83 ec 01 c6 45 ff ff 8a 10 8a 31 38 f2 75 ?? c6 45 ff 00 84 d2 74 ?? 40 41 eb ?? 80 7d ff 00 89 ec 5d c2 08 00 } //1
		$a_03_3 = {8b 45 e4 03 45 e8 0f be 08 33 ca 8b 55 e4 03 55 e8 88 0a e9 ?? ?? ?? ?? 8b 45 e4 eb ?? 33 c0 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}