
rule Backdoor_Win32_Zegost_CH{
	meta:
		description = "Backdoor:Win32/Zegost.CH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 3d 7e 00 75 02 33 c0 8a 1e 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 d1 32 d3 40 f6 d2 88 16 41 46 66 3b cf 72 da } //2
		$a_03_1 = {c6 85 38 ff ff ff 47 c6 85 39 ff ff ff 65 c6 85 3a ff ff ff 74 c6 85 3b ff ff ff 49 c6 85 3c ff ff ff 6e c6 85 3d ff ff ff 70 c6 85 3e ff ff ff 75 c6 85 3f ff ff ff 74 c6 85 40 ff ff ff 53 c6 85 41 ff ff ff 74 c6 85 42 ff ff ff 61 c6 85 43 ff ff ff 74 c6 85 44 ff ff ff 65 c6 85 45 ff ff ff 00 ff d6 8b 1d ?? ?? ?? ?? 50 ff d3 } //1
		$a_01_2 = {c6 44 24 0c 44 c6 44 24 0f 50 c6 44 24 10 72 c6 44 24 11 6f c6 44 24 12 78 c6 44 24 13 79 c6 44 24 14 4f c6 44 24 15 70 c6 44 24 16 65 c6 44 24 17 6e c6 44 24 18 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}