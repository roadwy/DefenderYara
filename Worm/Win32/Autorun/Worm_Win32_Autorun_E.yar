
rule Worm_Win32_Autorun_E{
	meta:
		description = "Worm:Win32/Autorun.E,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 07 00 00 "
		
	strings :
		$a_00_0 = {48 6f 6f 6b 2e 64 6c 6c } //10 Hook.dll
		$a_00_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10 DllCanUnloadNow
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_3 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //10 MsgHookOff
		$a_01_4 = {4d 73 67 48 6f 6f 6b 4f 6e } //10 MsgHookOn
		$a_00_5 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 4c 00 4c 00 } //10 Microsoft Corporation Windows DLL
		$a_02_6 = {50 50 c6 40 fb e9 83 68 fc 06 2b 40 03 51 b9 ?? ?? ?? ?? 81 34 08 ?? ?? ?? ?? e2 f7 59 c3 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_02_6  & 1)*10) >=70
 
}