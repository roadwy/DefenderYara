
rule TrojanDropper_Win32_Rovnix_A{
	meta:
		description = "TrojanDropper:Win32/Rovnix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4f 3c 48 8d 14 39 8b 4a 50 8b 5a 28 66 83 4a 16 01 } //1
		$a_01_1 = {66 b8 00 10 40 00 0f 23 d0 0f 21 f8 66 0d 2a 00 33 00 0f 23 f8 } //1
		$a_01_2 = {66 3d 46 4a 74 0d 83 c6 10 0f b7 06 66 85 c0 75 ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}