
rule Worm_Win32_Autorun_ZH{
	meta:
		description = "Worm:Win32/Autorun.ZH,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {68 fa 8b 34 00 ff b5 90 01 04 e8 90 00 } //1
		$a_00_1 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 } //1 Windows Update
		$a_00_2 = {4b 61 73 70 65 72 73 6b 79 20 55 70 64 61 74 65 } //1 Kaspersky Update
		$a_00_3 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //1 RtlDecompressBuffer
		$a_00_4 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_6 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule Worm_Win32_Autorun_ZH_2{
	meta:
		description = "Worm:Win32/Autorun.ZH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 78 63 68 6f 73 74 2e 65 78 65 } //2 sxchost.exe
		$a_01_1 = {69 63 6f 6e 3d 22 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c 2c 38 22 } //2 icon="%SystemRoot%\system32\SHELL32.dll,8"
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 c:\windows\system32\drivers\etc\hosts
		$a_01_3 = {68 74 74 70 3a 2f 2f 6d 61 73 75 6e 67 2e 73 65 6c 66 69 70 2e 62 69 7a 2f } //3 http://masung.selfip.biz/
		$a_01_4 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d } //2 shell\explore\Command=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=6
 
}
rule Worm_Win32_Autorun_ZH_3{
	meta:
		description = "Worm:Win32/Autorun.ZH,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_02_0 = {46 69 6c 65 4e 61 6d 65 41 63 74 75 61 6c 90 02 20 46 69 72 73 74 49 6e 73 74 61 6c 6c 90 02 10 64 64 6f 73 65 72 90 02 10 55 53 42 90 00 } //10
		$a_00_1 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_00_2 = {73 68 65 6c 6c 3d 76 65 72 62 } //1 shell=verb
		$a_00_3 = {61 63 74 69 6f 6e 3d 4f 70 65 6e 20 66 6f 6c 64 65 72 20 74 6f 20 76 69 65 77 20 66 69 6c 65 73 } //1 action=Open folder to view files
		$a_00_4 = {69 63 6f 6e 3d 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c 2c 34 } //1 icon=%SystemRoot%\system32\SHELL32.dll,4
		$a_00_5 = {55 53 42 7c 7c 2a 7c 7c 49 6e 66 65 63 74 65 64 20 44 72 69 76 65 20 } //1 USB||*||Infected Drive 
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=13
 
}