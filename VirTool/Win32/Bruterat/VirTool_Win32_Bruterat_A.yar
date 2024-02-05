
rule VirTool_Win32_Bruterat_A{
	meta:
		description = "VirTool:Win32/Bruterat.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {5d 20 25 73 20 50 61 73 73 77 6f 72 64 20 48 69 73 74 6f 72 79 3a } //] %s Password History:  01 00 
		$a_80_1 = {5d 20 53 41 4d 20 55 73 65 72 6e 61 6d 65 3a } //] SAM Username:  01 00 
		$a_80_2 = {43 72 61 63 6b 4e 61 6d 65 73 3a 20 30 78 } //CrackNames: 0x  01 00 
		$a_80_3 = {5d 20 53 79 6e 63 69 6e 67 20 44 43 3a } //] Syncing DC:  01 00 
		$a_80_4 = {5d 20 55 73 65 72 20 68 61 73 20 41 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 } //] User has Admin privileges  01 00 
		$a_80_5 = {5d 20 53 70 6f 6f 66 65 64 20 61 72 67 75 6d 65 6e 74 3a } //] Spoofed argument:  01 00 
		$a_80_6 = {5d 20 54 6f 6b 65 6e 20 52 69 6e 67 20 61 64 61 70 74 65 72 } //] Token Ring adapter  01 00 
		$a_80_7 = {5d 20 41 63 74 69 76 65 20 52 6f 75 74 65 73 3a } //] Active Routes:  01 00 
		$a_80_8 = {5d 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 3a } //] Impersonated:  01 00 
		$a_80_9 = {5d 20 43 72 69 73 69 73 20 4d 6f 6e 69 74 6f 72 3a } //] Crisis Monitor:  01 00 
		$a_80_10 = {5d 20 52 75 6e 6e 69 6e 67 20 64 6f 74 6e 65 74 5f 76 25 6c 75 } //] Running dotnet_v%lu  01 00 
		$a_80_11 = {5d 20 53 63 72 65 65 6e 73 68 6f 74 20 64 6f 77 6e 6c 6f 61 64 65 64 3a } //] Screenshot downloaded:  00 00 
		$a_00_12 = {5d 04 00 00 e9 38 } //05 80 
	condition:
		any of ($a_*)
 
}