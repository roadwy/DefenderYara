
rule PWS_Win32_QQpass_DA{
	meta:
		description = "PWS:Win32/QQpass.DA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 00 c3 00 00 75 73 65 72 33 32 2e 64 6c 6c 00 00 53 65 74 54 68 72 65 61 64 44 65 73 6b 74 6f 70 00 00 00 00 54 61 73 6b 4d 67 72 2e 65 78 45 00 55 8b ec 33 c0 55 } //01 00 
		$a_00_1 = {48 6f 6f 6b 2e 64 6c 6c } //01 00  Hook.dll
		$a_01_2 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //01 00  MsgHookOff
		$a_01_3 = {4d 73 67 48 6f 6f 6b 4f 6e } //01 00  MsgHookOn
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}