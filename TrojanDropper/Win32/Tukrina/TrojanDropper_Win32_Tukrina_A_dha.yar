
rule TrojanDropper_Win32_Tukrina_A_dha{
	meta:
		description = "TrojanDropper:Win32/Tukrina.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {25 73 5c 25 73 2e 74 6c 62 } //%s\%s.tlb  01 00 
		$a_80_1 = {25 73 5c 25 73 2e 69 6e 69 } //%s\%s.ini  01 00 
		$a_80_2 = {25 73 5c 25 73 2e 64 61 74 } //%s\%s.dat  02 00 
		$a_80_3 = {52 75 6e 44 6c 6c 33 32 2e 65 78 65 20 22 00 } //RunDll32.exe "  02 00 
		$a_80_4 = {22 20 53 74 61 72 74 52 6f 75 74 69 6e 65 00 } //" StartRoutine  02 00 
		$a_80_5 = {22 2c 49 6e 73 74 61 6c 6c 52 6f 75 74 69 6e 65 20 00 } //",InstallRoutine   00 00 
	condition:
		any of ($a_*)
 
}