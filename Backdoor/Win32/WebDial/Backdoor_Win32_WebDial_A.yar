
rule Backdoor_Win32_WebDial_A{
	meta:
		description = "Backdoor:Win32/WebDial.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 57 65 62 64 69 61 6c 65 72 5c } //01 00  Software\Webdialer\
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 57 65 62 64 69 61 6c 65 72 20 2d 20 20 52 65 67 2e 4e } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Webdialer -  Reg.N
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {59 6f 75 20 6d 75 73 74 20 62 65 20 65 69 67 68 74 65 65 6e 20 28 31 38 29 20 79 65 61 72 73 20 6f 66 20 61 67 65 20 6f 72 20 6f 6c 64 65 72 20 74 6f 20 75 73 65 20 74 68 69 73 20 73 65 72 76 69 63 65 2e } //01 00  You must be eighteen (18) years of age or older to use this service.
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}