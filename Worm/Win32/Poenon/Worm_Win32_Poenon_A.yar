
rule Worm_Win32_Poenon_A{
	meta:
		description = "Worm:Win32/Poenon.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 2f 00 76 00 20 00 4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 54 00 79 00 70 00 65 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 20 00 2f 00 64 00 20 00 3a 00 30 00 30 00 30 00 30 00 30 00 30 00 66 00 66 00 20 00 2f 00 66 00 } //1 policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d :000000ff /f
		$a_01_1 = {3a 00 5c 00 24 00 54 00 6d 00 70 00 5c 00 63 00 6c 00 65 00 61 00 6e 00 2e 00 65 00 78 00 65 00 } //1 :\$Tmp\clean.exe
		$a_01_2 = {6c 00 61 00 62 00 65 00 6c 00 3d 00 50 00 45 00 4e 00 44 00 52 00 49 00 56 00 45 00 } //1 label=PENDRIVE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Worm_Win32_Poenon_A_2{
	meta:
		description = "Worm:Win32/Poenon.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 2f 00 76 00 20 00 4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 54 00 79 00 70 00 65 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 20 00 2f 00 64 00 20 00 3a 00 30 00 30 00 30 00 30 00 30 00 30 00 66 00 66 00 20 00 2f 00 66 00 } //1 policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d :000000ff /f
		$a_01_1 = {50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 2f 00 76 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 20 00 2f 00 64 00 20 00 31 00 20 00 2f 00 66 00 } //1 Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
		$a_01_2 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 24 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 } //1 shell\Open\command=$windows
		$a_01_3 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 3d 00 31 00 } //1 shell\Open\Default=1
		$a_01_4 = {6c 00 61 00 62 00 65 00 6c 00 3d 00 50 00 45 00 4e 00 44 00 52 00 49 00 56 00 45 00 } //1 label=PENDRIVE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}