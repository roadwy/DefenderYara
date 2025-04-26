
rule TrojanDownloader_Win32_Adload_AMK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Adload.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 "
		
	strings :
		$a_80_0 = {53 79 73 4c 69 73 74 56 69 65 77 33 32 } //SysListView32  3
		$a_80_1 = {79 61 70 70 2e 65 78 65 } //yapp.exe  3
		$a_80_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //ShellExecuteExW  3
		$a_80_3 = {45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 57 } //ExpandEnvironmentStringsW  3
		$a_80_4 = {5b 52 65 6e 61 6d 65 5d } //[Rename]  3
		$a_80_5 = {25 6c 73 3d 25 6c 73 } //%ls=%ls  3
		$a_80_6 = {45 78 65 63 75 74 65 46 69 6c 65 } //ExecuteFile  3
		$a_80_7 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //unknowndll.pdb  3
		$a_80_8 = {45 4d 50 5c 6e 73 6b } //EMP\nsk  3
		$a_80_9 = {40 70 70 2e 65 78 65 } //@pp.exe  3
		$a_80_10 = {25 73 25 53 2e 64 6c 6c } //%s%S.dll  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3) >=33
 
}
rule TrojanDownloader_Win32_Adload_AMK_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/Adload.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0c 00 00 "
		
	strings :
		$a_80_0 = {45 6d 62 61 72 63 61 64 65 72 6f 20 52 41 44 20 53 74 75 64 69 6f } //Embarcadero RAD Studio  3
		$a_80_1 = {44 62 67 50 72 6f 6d 70 74 } //DbgPrompt  3
		$a_80_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //DllInstall  3
		$a_80_3 = {62 6f 72 6c 6e 64 6d 6d } //borlndmm  3
		$a_80_4 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  3
		$a_80_5 = {53 74 75 62 2e 65 78 65 } //Stub.exe  3
		$a_80_6 = {44 62 67 51 75 65 72 79 44 65 62 75 67 46 69 6c 74 65 72 53 74 61 74 65 } //DbgQueryDebugFilterState  3
		$a_80_7 = {4e 74 4e 6f 74 69 66 79 43 68 61 6e 67 65 4b 65 79 } //NtNotifyChangeKey  3
		$a_80_8 = {4c 64 72 55 6e 6c 6f 63 6b 4c 6f 61 64 65 72 4c 6f 63 6b } //LdrUnlockLoaderLock  3
		$a_80_9 = {53 69 6d 70 6c 79 53 79 6e 63 20 42 61 63 6b 75 70 } //SimplySync Backup  3
		$a_80_10 = {66 79 43 68 61 6e 67 65 4b 65 79 } //fyChangeKey  3
		$a_80_11 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //kLoaderLock  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3+(#a_80_11  & 1)*3) >=36
 
}