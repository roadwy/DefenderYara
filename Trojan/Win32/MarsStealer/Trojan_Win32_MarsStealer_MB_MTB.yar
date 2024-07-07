
rule Trojan_Win32_MarsStealer_MB_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 f9 02 33 c1 0f b7 15 90 01 03 00 c1 fa 03 33 c2 0f b7 0d 90 01 03 00 c1 f9 05 33 c1 83 e0 01 a3 90 01 03 00 90 00 } //5
		$a_02_1 = {33 d2 b9 24 00 00 00 f7 f1 8b 85 e4 fe ff ff 8a 8a 90 01 03 00 88 8c 05 f8 fe ff ff 90 00 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5) >=10
 
}
rule Trojan_Win32_MarsStealer_MB_MTB_2{
	meta:
		description = "Trojan:Win32/MarsStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8d 94 11 90 01 04 8b 45 fc 03 45 e0 88 10 8b 4d fc 03 4d e0 0f b6 11 81 ea 8b 10 00 00 8b 45 fc 03 45 e0 88 10 c7 45 f0 01 00 00 00 8b 4d f8 83 c1 01 89 4d f8 e9 90 00 } //10
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57 } //1 Process32FirstW
		$a_01_3 = {53 6c 65 65 70 } //1 Sleep
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_5 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_6 = {53 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 SetKeyboardState
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}