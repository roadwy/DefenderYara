
rule Trojan_Win32_Dridex_PJ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 9e 64 b3 82 42 ed fe 8d 6f 2d 0b 2b 01 59 ae d9 53 fd a0 51 c7 20 c1 9c 67 64 2b 1f 96 40 45 4a 1e e4 d2 83 2e ed 1e 0d a2 ac 3e 2b cd 8c c2 } //1
		$a_81_1 = {48 42 49 54 4d 41 50 5f 55 73 65 72 53 69 7a 65 } //1 HBITMAP_UserSize
		$a_81_2 = {50 6f 6c 79 6c 69 6e 65 54 6f } //1 PolylineTo
		$a_81_3 = {53 77 69 74 63 68 54 6f 54 68 69 73 57 69 6e 64 6f 77 } //1 SwitchToThisWindow
		$a_81_4 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } //1 LoadKeyboardLayoutA
		$a_81_5 = {4f 70 65 6e 53 65 6d 61 70 68 6f 72 65 57 } //1 OpenSemaphoreW
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}