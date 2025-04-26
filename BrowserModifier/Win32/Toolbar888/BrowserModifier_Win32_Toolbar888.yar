
rule BrowserModifier_Win32_Toolbar888{
	meta:
		description = "BrowserModifier:Win32/Toolbar888,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 19 00 06 00 00 "
		
	strings :
		$a_01_0 = {7b 43 31 42 34 44 45 43 32 2d 32 36 32 33 2d 34 33 38 65 2d 39 43 41 32 2d 43 39 30 34 33 41 42 32 38 35 30 38 7d } //10 {C1B4DEC2-2623-438e-9CA2-C9043AB28508}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 42 61 72 38 38 38 } //10 Software\Microsoft\Windows\CurrentVersion\Uninstall\Bar888
		$a_01_2 = {42 61 72 38 38 38 2e 64 6c 6c } //3 Bar888.dll
		$a_01_3 = {61 6e 64 20 63 6c 69 63 6b 20 59 45 53 20 74 6f 20 63 6f 6e 74 69 6e 75 65 20 75 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e } //3 and click YES to continue uninstallation.
		$a_01_4 = {55 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 61 62 6f 72 74 65 64 2e } //1 Uninstallation aborted.
		$a_01_5 = {53 79 73 74 65 6d 42 69 6f 73 44 61 74 65 } //1 SystemBiosDate
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=25
 
}