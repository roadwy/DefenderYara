
rule Worm_Win32_Autorun_BO{
	meta:
		description = "Worm:Win32/Autorun.BO,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_02_0 = {5b 61 75 74 6f 72 75 6e 5d 90 02 10 61 75 74 6f 72 75 6e 2e 69 6e 66 90 02 10 61 75 74 6f 72 75 6e 2e 65 78 65 90 02 10 5c 5c 3f 5c 25 63 3a 90 00 } //10
		$a_00_1 = {73 79 73 64 65 62 2e 69 6e 69 00 00 5c 64 65 62 75 67 5c 00 6d 73 6d 73 67 73 2e 65 78 65 } //10
		$a_01_2 = {48 4f 53 54 00 00 00 00 55 53 42 44 52 49 56 45 52 00 } //10
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {57 69 6e 64 6f 77 73 20 4d 65 73 73 65 6e 67 65 72 } //1 Windows Messenger
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=32
 
}