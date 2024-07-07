
rule Worm_Win32_Malas{
	meta:
		description = "Worm:Win32/Malas,SIGNATURE_TYPE_PEHSTR,4d 01 4d 01 10 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //100 \svchost.exe
		$a_01_1 = {6f 70 65 6e 3d 61 75 74 6f 70 6c 79 2e 65 78 65 20 4f 50 45 4e } //100 open=autoply.exe OPEN
		$a_01_2 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //100 C:\WINDOWS\system32\cmd.exe
		$a_01_3 = {5b 61 75 74 6f 72 75 6e 5d } //10 [autorun]
		$a_01_4 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74 3d 31 } //10 shell\open\Default=1
		$a_01_5 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 3d 45 78 70 6c 6f 72 65 } //10 shell\explore=Explore
		$a_01_6 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 61 75 74 6f 70 6c 79 2e 65 78 65 } //10 shell\open\Command=autoply.exe
		$a_01_7 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 61 75 74 6f 70 6c 79 2e 65 78 65 } //10 shell\explore\Command=autoply.exe
		$a_01_8 = {73 68 65 6c 6c 5c 41 75 74 6f 50 6c 61 79 5c 43 6f 6d 6d 61 6e 64 3d 61 75 74 6f 70 6c 79 2e 65 78 65 } //10 shell\AutoPlay\Command=autoply.exe
		$a_01_9 = {57 4e 65 74 4f 70 65 6e 45 6e 75 6d 57 } //1 WNetOpenEnumW
		$a_01_10 = {57 4e 65 74 45 6e 75 6d 52 65 73 6f 75 72 63 65 57 } //1 WNetEnumResourceW
		$a_01_11 = {4e 65 74 53 68 61 72 65 41 64 64 } //1 NetShareAdd
		$a_01_12 = {4d 6f 76 65 46 69 6c 65 57 } //1 MoveFileW
		$a_01_13 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //1 FindFirstFileW
		$a_01_14 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //1 FindNextFileW
		$a_01_15 = {53 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //1 SetProcessShutdownParameters
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=333
 
}