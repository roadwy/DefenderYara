
rule Worm_Win32_Autorun_PD{
	meta:
		description = "Worm:Win32/Autorun.PD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 :\autorun.inf
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 6d 73 76 64 33 32 73 72 76 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\msvd32srv
		$a_03_2 = {2d 77 61 69 74 90 02 18 6d 73 76 64 33 32 73 72 76 90 02 0c 2d 66 6c 61 73 68 90 02 0c 65 78 70 6c 6f 72 65 72 2e 65 78 65 90 02 0c 3a 5c 90 02 03 64 33 62 37 75 65 35 38 79 37 6a 62 64 73 90 00 } //1
		$a_01_3 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_03_4 = {2d 66 6c 61 73 68 90 02 0a 49 43 4f 4e 3d 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 34 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}