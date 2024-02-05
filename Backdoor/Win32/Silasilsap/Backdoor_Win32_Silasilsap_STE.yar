
rule Backdoor_Win32_Silasilsap_STE{
	meta:
		description = "Backdoor:Win32/Silasilsap.STE,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0e 00 00 01 00 "
		
	strings :
		$a_80_0 = {56 6e 63 53 74 61 72 74 53 65 72 76 65 72 } //VncStartServer  01 00 
		$a_80_1 = {56 6e 63 53 74 6f 70 53 65 72 76 65 72 } //VncStopServer  01 00 
		$a_80_2 = {62 6f 74 5f 73 68 65 6c 6c 20 3e } //bot_shell >  01 00 
		$a_80_3 = {42 4f 54 2d 25 73 28 25 73 29 5f 25 53 2d 25 53 25 75 25 75 } //BOT-%s(%s)_%S-%S%u%u  01 00 
		$a_80_4 = {55 53 52 2d 25 73 28 25 73 29 5f 25 53 2d 25 53 25 75 25 75 } //USR-%s(%s)_%S-%S%u%u  01 00 
		$a_02_5 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 90 02 10 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 73 00 3a 00 90 00 } //01 00 
		$a_02_6 = {70 61 73 73 77 6f 72 64 3a 90 02 10 63 6f 6d 6d 61 6e 64 73 3a 90 00 } //01 00 
		$a_80_7 = {41 63 74 69 76 65 44 6c 6c 3a 20 44 6c 6c 20 69 6e 6a 65 63 74 20 74 68 72 65 61 64 } //ActiveDll: Dll inject thread  01 00 
		$a_80_8 = {2a 2e 6e 65 76 65 72 73 65 65 6e 74 68 69 73 66 69 6c 65 } //*.neverseenthisfile  01 00 
		$a_80_9 = {62 6c 6f 63 6b 5f 69 6e 70 75 74 20 2f 20 75 6e 62 6c 6f 63 6b 5f 69 6e 70 75 74 } //block_input / unblock_input  01 00 
		$a_80_10 = {2f 6e 61 6d 65 20 4d 69 63 72 6f 73 6f 66 74 2e 50 6f 77 65 72 4f 70 74 69 6f 6e 73 } ///name Microsoft.PowerOptions  01 00 
		$a_80_11 = {50 73 53 75 70 3a 20 53 68 65 6c 6c 45 78 65 63 75 74 65 } //PsSup: ShellExecute  01 00 
		$a_80_12 = {4d 4f 5a 5f 44 49 53 41 42 4c 45 5f 43 4f 4e 54 45 4e 54 5f 53 41 4e 44 42 4f 58 } //MOZ_DISABLE_CONTENT_SANDBOX  01 00 
		$a_80_13 = {77 69 6e 64 6f 77 73 2e 69 6d 6d 65 72 73 69 76 65 73 68 65 6c 6c 2e 73 65 72 76 69 63 65 70 72 6f 76 69 64 65 72 2e 64 6c 6c } //windows.immersiveshell.serviceprovider.dll  00 00 
		$a_00_14 = {5d 04 00 00 09 } //81 04 
	condition:
		any of ($a_*)
 
}