
rule TrojanDropper_Win32_Bewmecky_A{
	meta:
		description = "TrojanDropper:Win32/Bewmecky.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 79 fd 2e 75 17 80 79 fe 65 75 11 80 79 ff 78 75 0b 80 39 65 75 06 } //1
		$a_03_1 = {50 ff 75 08 ff 15 ?? ?? ?? ?? ff 75 e0 e8 ?? ?? ?? ?? 59 8b 4d e0 80 7c 08 fb 32 74 2a } //1
		$a_01_2 = {ff d3 6a 02 59 3b c1 74 17 8d 56 f8 ff 75 e4 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}