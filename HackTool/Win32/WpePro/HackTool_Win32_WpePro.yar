
rule HackTool_Win32_WpePro{
	meta:
		description = "HackTool:Win32/WpePro,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 50 45 50 52 4f } //1 WPEPRO
		$a_01_1 = {57 70 65 53 70 79 2e 64 6c 6c } //1 WpeSpy.dll
		$a_01_2 = {57 69 6e 73 6f 63 6b 53 70 79 2e 43 6c 69 65 6e 74 } //1 WinsockSpy.Client
		$a_01_3 = {43 4c 6f 67 67 69 6e 67 4f 70 74 69 6f 6e 73 50 61 67 65 } //1 CLoggingOptionsPage
		$a_01_4 = {57 50 45 2d 43 31 34 36 37 32 31 31 2d 37 43 38 39 2d 34 39 63 35 2d 38 30 31 41 2d 31 44 30 34 38 45 34 30 31 34 43 34 } //1 WPE-C1467211-7C89-49c5-801A-1D048E4014C4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}