
rule Trojan_Win32_RedLineStealer_ME_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 75 08 8a 04 0a 30 04 3e 46 3b 75 0c 72 } //1
		$a_01_1 = {83 65 9c 00 8b 45 9c 89 45 98 ff 75 98 ff 55 } //1
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_3 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //1 FindFirstFileExW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_RedLineStealer_ME_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b d7 d3 ea 89 45 f0 03 55 e4 33 d0 89 55 ec 8b 45 ec 29 45 f8 25 ?? ?? ?? ?? 8b 55 f8 8b c2 8d 4d f0 e8 ?? ?? ?? ?? 8b 4d d8 8b c2 c1 e8 ?? ?? ?? ?? 8d 45 ec e8 ?? ?? ?? ?? 8b 45 fc 03 c2 50 8b 45 f0 03 45 dc e8 ?? ?? ?? ?? ff 75 ec 8d 75 f0 89 45 f0 e8 ?? ?? ?? ?? 2b 7d f0 89 1d ?? ?? ?? ?? 8b 45 e0 29 45 fc ff 4d e8 0f } //1
		$a_00_1 = {c1 e0 04 89 01 c3 } //1
		$a_03_2 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}