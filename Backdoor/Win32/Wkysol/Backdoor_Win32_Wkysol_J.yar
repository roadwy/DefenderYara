
rule Backdoor_Win32_Wkysol_J{
	meta:
		description = "Backdoor:Win32/Wkysol.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {2f 70 75 74 2e 61 73 70 3f 6e 6d 3d } //1 /put.asp?nm=
		$a_01_2 = {2f 67 65 74 2e 61 73 70 3f 6e 6d 3d 69 6e 64 65 78 2e 64 61 74 } //1 /get.asp?nm=index.dat
		$a_01_3 = {52 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 20 02 00 00 6a 20 6a 02 8d 45 dc 50 ff 15 } //1
		$a_03_4 = {80 c9 80 89 8d 90 01 04 6a 04 8d 95 90 1b 00 52 6a 1f 8b 85 90 01 04 50 ff 15 90 00 } //1
		$a_01_5 = {8d 55 a8 52 53 53 53 53 53 53 68 20 02 00 00 6a 20 6a 02 8d 45 dc 50 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}