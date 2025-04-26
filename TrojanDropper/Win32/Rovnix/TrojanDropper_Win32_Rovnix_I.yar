
rule TrojanDropper_Win32_Rovnix_I{
	meta:
		description = "TrojanDropper:Win32/Rovnix.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 3c 30 33 75 09 81 3c 30 33 33 33 33 74 07 40 3b c7 72 ec } //2
		$a_01_1 = {8a 14 08 80 fa eb 75 0a 0f b6 4c 08 01 8d 44 08 02 c3 80 fa e9 75 0a 0f b7 54 08 01 8d 44 10 03 } //2
		$a_01_2 = {b9 46 4a 00 00 66 3b c1 74 1a 0f b7 46 14 83 c6 14 66 85 c0 75 ea ba 46 4a 00 00 } //2
		$a_01_3 = {ba 55 aa 00 00 66 39 93 fe 01 00 00 75 13 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}