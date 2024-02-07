
rule TrojanDropper_Win32_Conhook_A{
	meta:
		description = "TrojanDropper:Win32/Conhook.A,SIGNATURE_TYPE_PEHSTR,2c 00 2c 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 50 72 6f 63 } //0a 00  HookProc
		$a_01_1 = {72 65 6d 6f 76 61 6c 66 69 6c 65 2e 62 61 74 00 40 65 63 68 6f 20 6f 66 66 } //0a 00 
		$a_01_2 = {69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 64 66 } //0a 00  if exist %1 goto df
		$a_01_3 = {41 63 74 69 76 61 74 65 } //02 00  Activate
		$a_01_4 = {8b c0 50 58 90 } //02 00 
		$a_01_5 = {87 c0 87 db 86 db 90 } //02 00 
		$a_01_6 = {53 53 6a 02 53 53 } //02 00  卓ɪ卓
		$a_01_7 = {0f af c8 0f af 4d f0 0f af 4d f0 } //00 00 
	condition:
		any of ($a_*)
 
}