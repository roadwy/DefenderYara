
rule Worm_Win32_Autorun_BT{
	meta:
		description = "Worm:Win32/Autorun.BT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 65 67 65 62 61 7a 69 64 65 71 } //1 malegebazideq
		$a_01_1 = {77 6f 63 61 6f 6e 69 6c 61 6f 6d 75 71 } //1 wocaonilaomuq
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_3 = {4d 73 67 48 6f 6f 6b 69 66 00 00 00 4d 73 67 48 6f 6f 6b 4f 70 } //1
		$a_03_4 = {57 69 6e 53 79 73 ?? ?? 2e 54 61 6f } //1
		$a_03_5 = {57 69 6e 53 79 73 ?? ?? 2e 53 79 73 } //1
		$a_01_6 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //1 shellexecute=AutoRun.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Worm_Win32_Autorun_BT_2{
	meta:
		description = "Worm:Win32/Autorun.BT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 65 67 65 62 61 7a 69 64 65 71 } //1 malegebazideq
		$a_01_1 = {77 6f 63 61 6f 6e 69 6c 61 6f 6d 75 71 } //1 wocaonilaomuq
		$a_01_2 = {20 2f 53 54 41 52 54 00 ff ff ff ff 07 00 00 00 20 51 51 55 49 4e 3a 00 ff ff ff ff } //1
		$a_01_3 = {54 65 6e 63 65 6e 74 5f 51 51 54 6f 6f 6c 42 61 72 } //1 Tencent_QQToolBar
		$a_01_4 = {20 51 51 50 53 57 3a 00 ff ff ff ff 09 00 00 00 20 2f 53 54 41 54 3a 31 30 00 } //1
		$a_00_5 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_01_6 = {4e 75 6d 62 65 72 3d 00 ff ff ff ff 0a 00 00 00 26 50 61 73 73 57 6f 72 64 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}