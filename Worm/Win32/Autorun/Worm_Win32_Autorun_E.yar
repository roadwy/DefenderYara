
rule Worm_Win32_Autorun_E{
	meta:
		description = "Worm:Win32/Autorun.E,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 6f 6f 6b 2e 64 6c 6c } //0a 00  Hook.dll
		$a_00_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //0a 00  DllCanUnloadNow
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //0a 00  DllRegisterServer
		$a_01_3 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //0a 00  MsgHookOff
		$a_01_4 = {4d 73 67 48 6f 6f 6b 4f 6e } //0a 00  MsgHookOn
		$a_00_5 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 4c 00 4c 00 } //0a 00  Microsoft Corporation Windows DLL
		$a_02_6 = {50 50 c6 40 fb e9 83 68 fc 06 2b 40 03 51 b9 90 01 04 81 34 08 90 01 04 e2 f7 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}