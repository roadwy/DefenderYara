
rule BrowserModifier_Win32_DCToolbar{
	meta:
		description = "BrowserModifier:Win32/DCToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 6f 6f 6c 62 61 72 5f 73 61 6d 70 6c 65 2e 64 6c 6c } //1 toolbar_sample.dll
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 61 64 76 70 61 63 6b 2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 20 22 } //1 rundll32.exe advpack.dll,DelNodeRunDLL32 "
		$a_01_2 = {7b 35 46 31 41 42 43 44 42 2d 41 38 37 35 2d 34 36 63 31 2d 38 33 34 35 2d } //3 {5F1ABCDB-A875-46c1-8345-
		$a_01_3 = {4d 61 6b 65 20 44 65 66 61 75 6c 74 20 54 6f 6f 6c 62 61 72 } //1 Make Default Toolbar
		$a_01_4 = {3e 60 23 64 6f 63 75 6d 65 6e 74 20 2d 20 64 6f 63 75 6d 65 6e 74 } //1 >`#document - document
		$a_01_5 = {45 72 72 6f 72 20 70 72 6f 63 65 73 73 69 6e 67 20 58 4d 4c 20 66 69 6c 65 3a 20 } //1 Error processing XML file: 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}