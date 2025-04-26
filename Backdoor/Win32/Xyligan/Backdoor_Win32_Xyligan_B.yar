
rule Backdoor_Win32_Xyligan_B{
	meta:
		description = "Backdoor:Win32/Xyligan.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 00 63 3a 5c 00 63 6d 64 2e 65 78 65 } //1
		$a_01_1 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4d 69 63 72 6f 73 6f 66 74 } //1 %s:*:Enabled:Microsoft
		$a_01_2 = {85 c0 74 31 8b 48 04 8b 54 24 0c 57 8b 78 08 8b 49 14 8b 32 8b d1 83 c0 14 c1 e9 02 f3 a5 8b ca 6a 00 83 e1 03 50 f3 a4 } //5
		$a_03_3 = {8b 44 24 10 50 ff d3 b9 41 00 00 00 33 c0 8d bc 24 ?? ?? ?? ?? 8d 94 24 ?? ?? ?? ?? f3 ab bf ?? ?? ?? 00 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 4c 24 24 33 ed 51 68 3f 00 0f 00 8d 94 24 ?? ?? ?? ?? 55 52 68 02 00 00 80 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_03_3  & 1)*5) >=12
 
}