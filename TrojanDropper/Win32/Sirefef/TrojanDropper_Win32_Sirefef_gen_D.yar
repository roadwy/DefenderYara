
rule TrojanDropper_Win32_Sirefef_gen_D{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e4 26 16 91 cc 1d 46 59 39 03 00 00 3c 77 cd 6b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDropper_Win32_Sirefef_gen_D_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8b 4d ?? 0f b7 04 41 ff 75 14 8b 4d ?? ff 75 10 8b 04 81 ff 75 0c 03 45 08 ff d0 } //100
		$a_03_1 = {8b d6 03 ce 2b d0 8b 45 ?? 8b (5d|7d) 90 1b 00 8a 8c 90 03 01 01 19 39 ?? ?? ?? ?? 88 8c 02 } //1
		$a_03_2 = {03 ce 8b d6 2b d0 8b 45 ?? 8b (5d|7d) 90 1b 00 8a 8c 90 03 01 01 19 39 ?? ?? ?? ?? 88 8c 02 } //1
		$a_03_3 = {f7 f3 8b d6 2b d0 8b 45 ?? 8b (5d|7d) 90 1b 00 8a 8c 90 03 01 01 19 39 ?? ?? ?? ?? 88 8c 02 } //1
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}