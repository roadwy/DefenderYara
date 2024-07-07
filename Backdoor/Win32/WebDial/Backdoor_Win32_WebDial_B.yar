
rule Backdoor_Win32_WebDial_B{
	meta:
		description = "Backdoor:Win32/WebDial.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 57 65 62 64 69 61 6c 65 72 5c } //1 Software\Webdialer\
		$a_00_1 = {52 65 67 2e 4e 3a 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 57 65 62 64 69 61 6c 65 72 20 2d } //1
		$a_00_2 = {52 61 73 44 69 61 6c 45 76 65 6e 74 00 00 00 00 2d 75 00 00 2d 64 00 00 53 74 61 72 74 20 50 61 67 65 } //1
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {49 66 20 79 6f 75 20 61 72 65 20 75 6e 64 65 72 20 31 38 20 79 65 61 72 73 20 6f 66 20 61 67 65 } //1 If you are under 18 years of age
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}