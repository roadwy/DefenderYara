
rule TrojanSpy_Win32_Savnut_A_dll{
	meta:
		description = "TrojanSpy:Win32/Savnut.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 00 43 00 4c 00 49 00 43 00 4b 00 4e 00 44 00 42 00 4c 00 } //1 LCLICKNDBL
		$a_01_1 = {73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 } //1 showpopup
		$a_01_2 = {25 00 30 00 31 00 30 00 64 00 2e 00 76 00 6b 00 65 00 79 00 2e 00 6a 00 70 00 67 00 } //1 %010d.vkey.jpg
		$a_01_3 = {74 00 76 00 62 00 6f 00 74 00 6f 00 66 00 66 00 } //1 tvbotoff
		$a_01_4 = {56 6b 65 79 47 72 61 62 62 65 72 57 } //1 VkeyGrabberW
		$a_01_5 = {57 65 73 74 70 61 63 6b 4f 6e 43 6c 69 63 6b 57 } //1 WestpackOnClickW
		$a_03_6 = {8b 4d cc 8b 55 f0 56 89 71 08 8b 42 f4 68 ?? ?? ?? 10 03 c0 50 52 ff 31 ff 15 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*3) >=3
 
}