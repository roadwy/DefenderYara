
rule TrojanSpy_Win32_Bzub_A{
	meta:
		description = "TrojanSpy:Win32/Bzub.A,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 08 00 00 "
		
	strings :
		$a_01_0 = {31 32 33 61 62 25 2e 38 6c 78 } //10 123ab%.8lx
		$a_01_1 = {49 65 48 6f 6f 6b 2e 64 6c 6c } //10 IeHook.dll
		$a_01_2 = {5c 68 6f 73 74 77 6c 2e 65 78 65 } //10 \hostwl.exe
		$a_01_3 = {5c 66 6c 61 73 68 2e 7a 69 70 } //10 \flash.zip
		$a_01_4 = {70 61 79 6d 65 6e 74 73 2e 61 73 70 } //10 payments.asp
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 http://www.microsoft.com
		$a_01_6 = {5c 4d 61 63 72 6f 6d 65 64 69 61 5c 46 6c 61 73 68 20 50 6c 61 79 65 72 } //1 \Macromedia\Flash Player
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=42
 
}