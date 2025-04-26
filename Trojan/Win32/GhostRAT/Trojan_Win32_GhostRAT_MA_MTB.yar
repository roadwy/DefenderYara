
rule Trojan_Win32_GhostRAT_MA_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 0f b6 45 10 99 b9 ?? ?? ?? ?? 53 f7 f9 56 57 89 65 f0 80 c2 17 83 65 ec 00 88 55 13 8b 45 ec 3b 45 0c 73 } //1
		$a_03_1 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 ?? ?? ?? ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_GhostRAT_MA_MTB_2{
	meta:
		description = "Trojan:Win32/GhostRAT.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 f8 81 ec 5c 0b 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 58 0b 00 00 53 56 57 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 } //5
		$a_01_1 = {5c 00 6a 00 69 00 73 00 75 00 70 00 64 00 66 00 2e 00 65 00 78 00 65 00 } //2 \jisupdf.exe
		$a_01_2 = {52 00 75 00 6e 00 4f 00 6e 00 6c 00 79 00 4f 00 6e 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //2 RunOnlyOneInstance
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}