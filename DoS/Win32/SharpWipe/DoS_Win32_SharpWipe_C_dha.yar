
rule DoS_Win32_SharpWipe_C_dha{
	meta:
		description = "DoS:Win32/SharpWipe.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {2d 00 72 00 20 00 2d 00 71 00 20 00 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 43 00 3a 00 5c 00 6d 00 79 00 61 00 70 00 70 00 2e 00 65 00 78 00 65 00 } //1 -r -q -accepteula C:\myapp.exe
		$a_01_1 = {2d 00 72 00 20 00 2d 00 73 00 20 00 2d 00 71 00 20 00 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 43 00 3a 00 5c 00 2a 00 } //1 -r -s -q -accepteula C:\*
		$a_01_2 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //1 \\.\PhysicalDrive0
		$a_01_3 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 31 00 } //1 \\.\PhysicalDrive1
		$a_01_4 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 32 00 } //1 \\.\PhysicalDrive2
		$a_01_5 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 33 00 } //1 \\.\PhysicalDrive3
		$a_01_6 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 34 00 } //1 \\.\PhysicalDrive4
		$a_01_7 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 35 00 } //1 \\.\PhysicalDrive5
		$a_01_8 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 36 00 } //1 \\.\PhysicalDrive6
		$a_01_9 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 37 00 } //1 \\.\PhysicalDrive7
		$a_01_10 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 38 00 } //1 \\.\PhysicalDrive8
		$a_01_11 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 39 00 } //1 \\.\PhysicalDrive9
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}