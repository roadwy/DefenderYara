
rule TrojanSpy_Win32_Maran_gen_B{
	meta:
		description = "TrojanSpy:Win32/Maran.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {77 6d 76 64 73 66 2e 61 78 } //5 wmvdsf.ax
		$a_01_2 = {74 78 74 00 77 65 62 63 66 67 00 } //1
		$a_01_3 = {78 78 78 78 78 2e 62 61 74 } //5 xxxxx.bat
		$a_01_4 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 0d 0a } //1
		$a_00_5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_01_6 = {68 74 6f 6e 73 } //1 htons
		$a_00_7 = {73 6f 63 6b 65 74 } //1 socket
		$a_01_8 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 41 } //1 StartServiceCtrlDispatcherA
		$a_01_9 = {53 65 74 53 65 72 76 69 63 65 53 74 61 74 75 73 } //1 SetServiceStatus
		$a_01_10 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //1 RegisterServiceCtrlHandlerA
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=28
 
}