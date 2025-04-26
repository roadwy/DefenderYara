
rule TrojanDropper_Win32_Sventore_A{
	meta:
		description = "TrojanDropper:Win32/Sventore.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce 66 33 04 7d ?? ?? ?? ?? 0f b7 c0 50 e8 ?? ?? ?? ?? 47 3b 7c 24 10 7c de } //1
		$a_01_1 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Sventore_A_2{
	meta:
		description = "TrojanDropper:Win32/Sventore.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b ce 66 33 04 7d ?? ?? ?? ?? 0f b7 c0 50 e8 ?? ?? ?? ?? 47 3b [0-03] 7c } //1
		$a_03_1 = {2b f9 66 8b 8c 56 ?? ?? ?? ?? 66 33 0c 55 ?? ?? ?? ?? 42 66 89 8c 57 ?? ?? ?? ?? 3b 55 0c 7c e2 } //1
		$a_03_2 = {2b c8 66 8b 84 73 ?? ?? ?? ?? 66 33 04 75 ?? ?? ?? ?? 66 89 84 71 ?? ?? ?? ?? 46 3b f2 7c e3 } //1
		$a_03_3 = {8b 56 14 0f b7 d8 83 fa 08 72 04 90 09 10 00 66 8b 84 78 ?? ?? ?? ?? 66 33 04 7d } //1
		$a_01_4 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6 } //1
		$a_03_5 = {50 75 15 80 7c ?? 01 4b 75 0e 80 7c ?? 02 05 75 07 80 7c ?? 03 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=1
 
}