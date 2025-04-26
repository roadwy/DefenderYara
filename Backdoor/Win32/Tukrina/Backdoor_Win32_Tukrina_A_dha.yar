
rule Backdoor_Win32_Tukrina_A_dha{
	meta:
		description = "Backdoor:Win32/Tukrina.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_80_0 = {6e 6f 72 77 61 79 6e 65 77 73 2e 6d 6f 6f 6f 2e 63 6f 6d } //norwaynews.mooo.com  2
		$a_80_1 = {65 62 61 79 2d 67 6c 6f 62 61 6c 2e 70 75 62 6c 69 63 76 6d 2e 63 6f 6d } //ebay-global.publicvm.com  2
		$a_80_2 = {70 73 79 63 68 6f 6c 6f 67 79 2d 62 6c 6f 67 2e 65 7a 75 61 2e 63 6f 6d } //psychology-blog.ezua.com  2
		$a_80_3 = {2f 73 63 72 69 70 74 73 2f 6d 2f 71 75 65 72 79 2e 70 68 70 3f 69 64 3d } ///scripts/m/query.php?id=  3
		$a_80_4 = {4d 69 63 72 6f 73 6f 66 74 20 55 70 64 61 74 65 } //Microsoft Update  1
		$a_80_5 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_6 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 34 31 2e 30 2e 32 32 32 38 2e 30 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 } //Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36  1
		$a_00_7 = {53 74 61 72 74 52 6f 75 74 69 6e 65 } //1 StartRoutine
		$a_00_8 = {49 6e 73 74 61 6c 6c 52 6f 75 74 69 6e 65 57 } //1 InstallRoutineW
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*3+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=5
 
}