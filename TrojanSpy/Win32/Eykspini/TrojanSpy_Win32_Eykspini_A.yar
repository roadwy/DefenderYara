
rule TrojanSpy_Win32_Eykspini_A{
	meta:
		description = "TrojanSpy:Win32/Eykspini.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 00 65 00 79 00 42 00 6f 00 61 00 72 00 64 00 53 00 70 00 79 00 2e 00 76 00 62 00 70 00 } //1 KeyBoardSpy.vbp
		$a_01_1 = {4b 65 79 5f 73 70 79 20 3a 20 } //1 Key_spy : 
		$a_00_2 = {6d 00 73 00 64 00 66 00 6d 00 61 00 70 00 2e 00 69 00 6e 00 69 00 } //1 msdfmap.ini
		$a_01_3 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}