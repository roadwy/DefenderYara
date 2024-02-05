
rule Trojan_BAT_Starter_EA_MTB{
	meta:
		description = "Trojan:BAT/Starter.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 0d 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0a 06 72 01 90 01 02 70 28 90 01 03 0a 28 90 01 03 06 26 06 72 90 01 03 70 28 90 01 03 0a 28 90 01 03 06 26 2a 90 00 } //03 00 
		$a_80_1 = {5c 53 79 73 74 65 6d 5c 63 73 72 73 73 2e 65 78 65 } //\System\csrss.exe  03 00 
		$a_80_2 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //get_StartupPath  03 00 
		$a_80_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  02 00 
		$a_80_4 = {43 6f 6d 70 69 6c 65 54 65 73 74 } //CompileTest  02 00 
		$a_80_5 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //HideModuleNameAttribute  00 00 
	condition:
		any of ($a_*)
 
}