
rule Worm_Win32_Autorun_gen_BE{
	meta:
		description = "Worm:Win32/Autorun.gen!BE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_01_1 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 6b 00 61 00 76 00 73 00 72 00 76 00 2e 00 65 00 78 00 65 00 } //1 shell\open\command=kavsrv.exe
		$a_01_2 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 44 00 58 00 47 00 44 00 49 00 41 00 4c 00 4f 00 47 00 2e 00 45 00 58 00 45 00 00 00 } //1
		$a_01_3 = {44 00 72 00 69 00 76 00 65 00 54 00 79 00 70 00 65 00 } //1 DriveType
		$a_01_4 = {53 00 75 00 62 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 } //1 SubFolders
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}