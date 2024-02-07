
rule PWS_Win32_Agent_AD{
	meta:
		description = "PWS:Win32/Agent.AD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 54 65 6e 63 65 6e 74 5c 47 6d } //01 00  Software\Tencent\Gm
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 32 36 2e 63 6e 2f } //01 00  http://www.126.cn/
		$a_01_2 = {54 65 6e 63 65 6e 74 5f 51 51 54 6f 6f 6c 42 61 72 } //01 00  Tencent_QQToolBar
		$a_01_3 = {45 78 70 6c 4f 72 65 72 2e 65 78 65 } //01 00  ExplOrer.exe
		$a_01_4 = {53 79 73 57 69 6e 36 34 2e 4a 6d 70 } //01 00  SysWin64.Jmp
		$a_01_5 = {53 79 73 57 69 6e 36 34 2e 4c 73 74 } //01 00  SysWin64.Lst
		$a_00_6 = {26 50 61 73 73 57 6f 72 64 3d } //00 00  &PassWord=
	condition:
		any of ($a_*)
 
}