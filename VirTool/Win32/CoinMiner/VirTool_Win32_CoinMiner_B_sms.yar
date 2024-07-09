
rule VirTool_Win32_CoinMiner_B_sms{
	meta:
		description = "VirTool:Win32/CoinMiner.B!sms,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_03_0 = {2d 2d 61 6c 67 6f 3d [0-01] 72 78 2f 30 } //1
		$a_03_1 = {2d 2d 75 72 6c 3d [0-10] 2e [0-10] 2e [0-10] 3a [0-20] 2d 2d 75 73 65 72 3d } //1
		$a_03_2 = {2d 2d 70 61 73 73 3d [0-20] 2d 2d 63 70 75 2d 6d 61 78 2d 74 68 72 65 61 64 73 2d 68 69 6e 74 3d } //1
		$a_01_3 = {2d 2d 63 69 6e 69 74 2d 73 74 65 61 6c 74 68 2d 74 61 72 67 65 74 73 3d 54 61 73 6b 6d 67 72 2e 65 78 65 2c } //1 --cinit-stealth-targets=Taskmgr.exe,
		$a_01_4 = {2c 70 72 6f 63 65 78 70 2e 65 78 65 2c 70 72 6f 63 65 78 70 36 34 2e 65 78 65 } //1 ,procexp.exe,procexp64.exe
		$a_01_5 = {2d 2d 63 69 6e 69 74 2d 61 70 69 3d 68 74 74 70 } //1 --cinit-api=http
		$a_01_6 = {2d 2d 63 69 6e 69 74 2d 69 64 6c 65 2d 77 61 69 74 3d } //1 --cinit-idle-wait=
		$a_01_7 = {2d 2d 63 69 6e 69 74 2d 69 64 6c 65 2d 63 70 75 3d } //1 --cinit-idle-cpu=
		$a_01_8 = {2d 2d 63 69 6e 69 74 2d 6b 69 6c 6c 2d 74 61 72 67 65 74 73 3d } //1 --cinit-kill-targets=
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}