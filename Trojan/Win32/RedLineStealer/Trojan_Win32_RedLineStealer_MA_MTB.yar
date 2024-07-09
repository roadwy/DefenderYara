
rule Trojan_Win32_RedLineStealer_MA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {5c 00 6d 00 69 00 6a 00 65 00 78 00 5c 00 [0-0f] 6b 00 75 00 78 00 65 00 79 00 6f 00 72 00 5c 00 36 00 5c 00 [0-0f] 2e 00 70 00 64 00 62 00 } //10
		$a_02_1 = {5c 6d 69 6a 65 78 5c [0-0f] 6b 75 78 65 79 6f 72 5c 36 5c [0-0f] 2e 70 64 62 } //10
		$a_03_2 = {8b 01 ba ff ?? ?? ?? 03 d0 83 f0 ?? 33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 e8 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_03_2  & 1)*1) >=11
 
}
rule Trojan_Win32_RedLineStealer_MA_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 4d fc b8 3b 2d 0b 00 01 45 fc 8b 55 fc 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 0e 83 3d ?? ?? ?? ?? 44 75 ?? 8d 55 f4 52 68 ?? ?? ?? ?? ff ?? 6a ?? 6a ?? ff ?? 46 3b 35 ?? ?? ?? ?? 72 } //5
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_3 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //1 RaiseException
		$a_01_4 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}