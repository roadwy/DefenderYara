
rule PWS_Win32_GameSteal_A{
	meta:
		description = "PWS:Win32/GameSteal.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 2d 43 68 69 6e 61 } //01 00  E-China
		$a_00_1 = {57 6f 77 45 78 65 63 } //01 00  WowExec
		$a_00_2 = {57 6f 57 2e 65 78 65 00 } //01 00 
		$a_01_3 = {59 42 5f 4f 6e 6c 69 6e 65 43 6c 69 65 6e 74 } //01 00  YB_OnlineClient
		$a_00_4 = {23 33 32 37 37 30 } //01 00  #32770
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00  SetWindowsHookExA
	condition:
		any of ($a_*)
 
}