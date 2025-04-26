
rule Worm_Win32_Autorun_NB{
	meta:
		description = "Worm:Win32/Autorun.NB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_1 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_02_2 = {6f 70 65 6e 3d [0-10] 2e 65 78 65 } //1
		$a_02_3 = {69 63 6f 6e 3d [0-10] 2e 65 78 65 } //1
		$a_80_4 = {43 3a 5c 54 45 4d 50 5c 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //C:\TEMP\\autorun.inf  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}