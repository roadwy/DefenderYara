
rule Worm_Win32_Autorun_EQ{
	meta:
		description = "Worm:Win32/Autorun.EQ,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } //1 GetDiskFreeSpaceExA
		$a_01_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c 73 79 73 74 65 6d 73 2e 63 6f 6d } //1 shell\open\command=RECYCLER\systems.com
		$a_01_4 = {74 61 73 6b 6d 67 65 72 2e 63 6f 6d } //1 taskmger.com
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_6 = {4d 79 50 69 63 74 75 72 65 73 2e 65 78 65 } //1 MyPictures.exe
		$a_01_7 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } //1 DisableTaskmgr
		$a_01_8 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_01_9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}