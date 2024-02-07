
rule PWS_Win32_Nabfeign_A{
	meta:
		description = "PWS:Win32/Nabfeign.A,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 08 00 00 14 00 "
		
	strings :
		$a_01_0 = {4e 00 54 00 20 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 20 00 26 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //14 00  NT Kernel & System
		$a_00_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //0a 00  Internet Explorer_Server
		$a_01_2 = {26 70 77 64 3d 25 73 } //0a 00  &pwd=%s
		$a_01_3 = {26 63 6c 61 73 73 3d } //04 00  &class=
		$a_01_4 = {4b 65 79 48 6f 6f 6b } //04 00  KeyHook
		$a_01_5 = {67 61 6d 65 5f 70 77 64 } //01 00  game_pwd
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_7 = {57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00  WindowsHookEx
	condition:
		any of ($a_*)
 
}