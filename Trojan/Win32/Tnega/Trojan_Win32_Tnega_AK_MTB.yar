
rule Trojan_Win32_Tnega_AK_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 14 53 56 57 89 65 e8 e9 } //3
		$a_01_1 = {62 00 6d 00 70 00 72 00 65 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 bmpres.dll
		$a_01_2 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //1 kLoaderLock
		$a_01_3 = {4c 64 72 55 6e 6c 6f 63 6b 4c 6f 61 64 65 72 4c 6f 63 6b } //1 LdrUnlockLoaderLock
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule Trojan_Win32_Tnega_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Tnega.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 53 50 72 6f 74 65 63 74 5c 4b 65 79 } //1 Software\ASProtect\Key
		$a_01_1 = {61 73 70 72 5f 6b 65 79 73 2e 69 6e 69 } //1 aspr_keys.ini
		$a_01_2 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 } //1 Debugger detected
		$a_01_3 = {72 75 6e 6e 69 6e 67 20 61 20 64 65 62 75 67 67 65 72 21 } //1 running a debugger!
		$a_01_4 = {57 6b 42 79 63 6d 39 71 5a 32 56 78 62 47 6c 6f 53 57 5a 6c 62 56 51 6c 4b 6c 46 64 62 6e 35 2f 5a 47 4a 67 55 79 4d 76 48 52 70 4b 49 7a 77 6e 4a 54 4e 32 59 58 78 35 63 6a 59 6e 4a 44 59 70 4c 6b 51 32 4f 6b 42 61 65 48 46 30 63 33 64 74 61 32 31 42 56 45 35 54 66 77 77 3d } //1 WkBycm9qZ2VxbGloSWZlbVQlKlFdbn5/ZGJgUyMvHRpKIzwnJTN2YXx5cjYnJDYpLkQ2OkBaeHF0c3dta21BVE5Tfww=
		$a_01_5 = {50 6c 65 61 73 65 20 72 75 6e 20 61 20 76 69 72 75 73 2d 63 68 65 63 6b } //1 Please run a virus-check
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}