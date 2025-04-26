
rule TrojanDropper_Win32_Daonol_E{
	meta:
		description = "TrojanDropper:Win32/Daonol.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 61 75 64 69 6f 2e 73 79 73 00 } //1
		$a_01_1 = {61 75 78 00 } //1 畡x
		$a_01_2 = {3a 5c 5f 2e 65 } //1 :\_.e
		$a_01_3 = {80 f1 d5 88 4c 02 ff 4a 75 f2 c3 } //2
		$a_03_4 = {c7 44 24 04 2e 2e 5c 00 54 68 3f 00 0f 00 6a 00 b8 ?? ?? ?? ?? ba 37 00 00 00 } //2
		$a_03_5 = {4e 83 fe 00 7c 16 b8 19 00 00 00 e8 ?? ?? ff ff 83 c0 61 88 03 43 4e 83 fe ff 75 ea c6 03 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2) >=6
 
}