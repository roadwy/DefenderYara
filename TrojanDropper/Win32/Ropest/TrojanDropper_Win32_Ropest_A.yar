
rule TrojanDropper_Win32_Ropest_A{
	meta:
		description = "TrojanDropper:Win32/Ropest.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 e8 0d 0f 84 ?? ?? ?? ?? 48 74 3f 2d 03 01 00 00 75 24 } //1
		$a_03_1 = {8b 48 3c 8b 4c 01 58 50 89 0d ?? ?? ?? ?? c6 45 ff 01 } //1
		$a_03_2 = {3d e4 85 43 31 0f 84 ?? ?? ?? ?? 3d f7 dc ee b1 0f 84 } //1
		$a_03_3 = {83 fe 04 72 02 33 f6 8a 14 01 32 96 ?? ?? ?? ?? 88 10 40 46 4f 75 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}