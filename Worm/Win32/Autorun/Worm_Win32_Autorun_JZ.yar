
rule Worm_Win32_Autorun_JZ{
	meta:
		description = "Worm:Win32/Autorun.JZ,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 64 00 65 00 6c 00 3d 00 48 00 65 00 6c 00 6c 00 6f 00 50 00 68 00 69 00 6c 00 69 00 70 00 70 00 69 00 6e 00 65 00 73 00 } //10 Model=HelloPhilippines
		$a_01_1 = {42 00 75 00 67 00 49 00 6e 00 64 00 65 00 70 00 65 00 6e 00 64 00 65 00 6e 00 74 00 5c 00 48 00 65 00 6c 00 6c 00 6f 00 50 00 68 00 69 00 6c 00 69 00 70 00 70 00 69 00 6e 00 65 00 73 00 2e 00 76 00 62 00 70 00 } //1 BugIndependent\HelloPhilippines.vbp
		$a_01_2 = {5c 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //1 \taskmgr.exe
		$a_01_3 = {41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 Autorun.inf
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}