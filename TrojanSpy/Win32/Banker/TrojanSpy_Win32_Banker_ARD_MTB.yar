
rule TrojanSpy_Win32_Banker_ARD_MTB{
	meta:
		description = "TrojanSpy:Win32/Banker.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 46 04 8b 56 08 33 c9 8a 0c 10 ff 46 08 83 46 10 01 83 56 14 00 84 db } //1
		$a_01_1 = {eb 7d 8b 44 24 0c 88 0c 28 45 83 fd 03 75 19 8b } //1
		$a_80_2 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 } //MapVirtualKey  1
		$a_80_3 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //GetKeyNameTextA  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}