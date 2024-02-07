
rule PWS_Win32_Hupigon{
	meta:
		description = "PWS:Win32/Hupigon,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 65 74 43 4e 6b 65 79 68 6f 6f 6b } //01 00  SetCNkeyhook
		$a_01_1 = {67 65 74 6b 65 79 2e 64 6c 6c } //01 00  getkey.dll
		$a_01_2 = {0b 5b 42 61 63 6b 73 70 61 63 65 5d } //01 00  嬋慂正灳捡嵥
		$a_01_3 = {43 54 52 4c 5f 41 4c 54 5f 44 45 4c 5f 47 45 54 4b 45 59 } //01 00  CTRL_ALT_DEL_GETKEY
		$a_01_4 = {57 69 6e 73 74 61 30 00 } //01 00  楗獮慴0
		$a_01_5 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_01_6 = {49 6d 6d 47 65 74 43 6f 6d 70 6f 73 69 74 69 6f 6e 53 74 72 69 6e 67 41 } //00 00  ImmGetCompositionStringA
	condition:
		any of ($a_*)
 
}