
rule Worm_Win32_Plurp_A{
	meta:
		description = "Worm:Win32/Plurp.A,SIGNATURE_TYPE_PEHSTR,40 00 3f 00 0c 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //10 CreateMutexA
		$a_01_1 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //10 MapViewOfFile
		$a_01_2 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //10 GetSystemDirectoryA
		$a_01_3 = {57 4e 65 74 45 6e 75 6d 52 65 73 6f 75 72 63 65 41 } //10 WNetEnumResourceA
		$a_01_4 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //10 EnumProcessModules
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 3b 20 66 69 6c 65 3d 50 75 72 70 6c 65 4d 6f 6f 64 2e 73 63 72 } //1 Content-Type: application/octet-stream; file=PurpleMood.scr
		$a_01_7 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 50 75 72 70 6c 65 4d 6f 6f 64 2e 73 63 72 } //1 Content-Disposition: attachment; filename=PurpleMood.scr
		$a_01_8 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 50 75 72 70 6c 65 4d 6f 6f 64 2e 73 63 72 } //1 C:\WINDOWS\system32\PurpleMood.scr
		$a_01_9 = {5c 50 75 72 70 6c 65 4d 6f 6f 64 2e 73 63 72 } //1 \PurpleMood.scr
		$a_01_10 = {70 61 63 74 35 31 38 2e 68 69 74 2e 65 64 75 2e 63 6e } //1 pact518.hit.edu.cn
		$a_01_11 = {48 45 4c 4f 20 63 78 } //1 HELO cx
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=63
 
}