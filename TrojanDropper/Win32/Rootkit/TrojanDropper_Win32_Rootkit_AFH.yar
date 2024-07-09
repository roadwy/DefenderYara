
rule TrojanDropper_Win32_Rootkit_AFH{
	meta:
		description = "TrojanDropper:Win32/Rootkit.AFH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7c 24 18 02 75 62 b8 cd cc cc cc f7 64 24 2c c1 ea 03 81 fa e8 03 00 00 73 07 ba e8 03 00 00 eb 0d } //1
		$a_03_1 = {68 80 00 00 00 6a 02 6a 00 6a 01 68 00 00 00 40 51 ff 15 ?? ?? 00 10 8d 54 24 0c 6a 00 52 8b f0 68 00 1a 00 00 68 ?? ?? 00 10 56 c7 44 24 20 00 00 00 00 ff 15 ?? ?? 00 10 } //1
		$a_00_2 = {62 65 65 70 2e 73 79 73 } //1 beep.sys
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Rootkit_AFH_2{
	meta:
		description = "TrojanDropper:Win32/Rootkit.AFH,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6f 6b 69 65 3a 20 41 53 50 53 45 53 53 49 4f 4e 49 44 41 43 51 41 44 52 44 54 3d 41 4d 43 4a 42 46 4a 41 4b 4a 41 50 4d 4e 49 4b 43 44 45 4e 47 49 49 42 } //1 Cookie: ASPSESSIONIDACQADRDT=AMCJBFJAKJAPMNIKCDENGIIB
		$a_00_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 64 65 73 6b 74 6f 70 } //1 software\microsoft\windows\currentversion\explorer\desktop
		$a_01_2 = {22 47 4e 47 4f 47 4c 56 41 4e 4b 47 4c 56 } //1 "GNGOGLVANKGLV
		$a_01_3 = {6d 6b 67 6f 24 6f 72 6f } //1 mkgo$oro
		$a_01_4 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1
		$a_00_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_6 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}
rule TrojanDropper_Win32_Rootkit_AFH_3{
	meta:
		description = "TrojanDropper:Win32/Rootkit.AFH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 64 65 73 6b 74 6f 70 00 00 73 79 73 66 69 6c 65 } //1
		$a_01_1 = {5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 00 43 4c 53 49 44 5c 00 00 7b 45 32 35 43 32 39 41 42 2d 31 32 42 39 2d 34 35 32 33 2d 41 35 33 43 2d 33 32 34 42 35 46 42 41 36 34 38 43 7d } //1
		$a_01_2 = {4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 53 48 45 4c 4c 45 58 45 43 55 54 45 48 4f 4f 4b 53 00 73 6f 66 74 77 61 72 65 5c } //1
		$a_01_3 = {22 25 73 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 22 20 22 25 73 5c 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 22 25 73 22 00 00 46 33 00 00 53 68 65 6c 6c } //1
		$a_01_4 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 00 6d 72 75 6c 69 73 74 00 25 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}