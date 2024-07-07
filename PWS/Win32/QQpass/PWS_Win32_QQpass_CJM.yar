
rule PWS_Win32_QQpass_CJM{
	meta:
		description = "PWS:Win32/QQpass.CJM,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 48 6f 6f 6b 4f 70 } //10 MsgHookOp
		$a_00_1 = {35 42 44 34 31 30 39 37 2d 33 36 39 33 2d 34 31 33 33 2d 38 32 30 45 2d 46 44 41 43 35 37 41 46 30 30 45 32 } //10 5BD41097-3693-4133-820E-FDAC57AF00E2
		$a_02_2 = {4e 76 57 69 6e 90 04 02 03 30 2d 39 2e 90 00 } //1
		$a_02_3 = {4e 76 53 79 73 90 04 02 03 30 2d 39 2e 90 00 } //1
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_5 = {77 69 6e 69 6e 69 74 2e 69 6e 69 } //1 wininit.ini
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}