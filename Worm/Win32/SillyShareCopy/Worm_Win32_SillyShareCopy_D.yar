
rule Worm_Win32_SillyShareCopy_D{
	meta:
		description = "Worm:Win32/SillyShareCopy.D,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //20 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //8 LoadResource
		$a_00_2 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //8 GetWindowsDirectoryA
		$a_00_3 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //8 CreateMutexA
		$a_01_4 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //1 ShowSuperHidden
		$a_01_5 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 CurrentVersion\Policies\Explorer\Run
		$a_00_6 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_7 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d } //1 shell\open\Command=
		$a_00_8 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_9 = {6e 65 74 2e 65 78 65 } //1 net.exe
		$a_01_10 = {2e 73 6d 31 00 } //1
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*8+(#a_00_2  & 1)*8+(#a_00_3  & 1)*8+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=50
 
}