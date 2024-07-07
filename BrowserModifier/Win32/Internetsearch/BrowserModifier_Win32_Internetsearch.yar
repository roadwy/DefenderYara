
rule BrowserModifier_Win32_Internetsearch{
	meta:
		description = "BrowserModifier:Win32/Internetsearch,SIGNATURE_TYPE_PEHSTR,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 74 65 72 6e 65 74 73 65 61 72 63 68 73 65 72 76 69 63 65 2e 63 6f 6d } //10 internetsearchservice.com
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 64 65 6c 20 2f 46 20 2f 51 20 22 25 73 5c 2a 2e 2a 22 } //10 cmd.exe /C del /F /Q "%s\*.*"
		$a_01_2 = {25 73 5c 25 73 2e 65 78 65 00 00 00 75 62 70 72 30 31 } //1
		$a_01_3 = {72 65 67 65 64 69 74 20 2f 73 20 63 3a 5c 74 6d 70 32 2e 72 65 67 } //1 regedit /s c:\tmp2.reg
		$a_01_4 = {64 65 6c 20 22 25 73 22 00 00 3a 54 58 32 30 32 } //1
		$a_01_5 = {73 65 61 72 63 68 00 00 69 65 36 2e 68 74 6d 6c } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}