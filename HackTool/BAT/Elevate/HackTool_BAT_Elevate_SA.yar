
rule HackTool_BAT_Elevate_SA{
	meta:
		description = "HackTool:BAT/Elevate.SA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 79 70 61 73 73 55 41 43 } //01 00  BypassUAC
		$a_01_1 = {41 00 74 00 74 00 65 00 6d 00 70 00 74 00 69 00 6e 00 67 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 } //01 00  Attempting Bypass
		$a_01_2 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 20 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 73 00 20 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 } //01 00  Administrator privileges required
		$a_01_3 = {44 69 73 61 62 6c 65 41 6c 6c 50 72 69 76 69 6c 65 67 65 73 } //05 00  DisableAllPrivileges
		$a_01_4 = {54 6f 6b 65 6e 76 61 74 6f 72 2e 70 64 62 } //01 00  Tokenvator.pdb
		$a_01_5 = {5b 00 21 00 5d 00 20 00 41 00 6e 00 74 00 69 00 2d 00 56 00 69 00 72 00 75 00 73 00 } //00 00  [!] Anti-Virus
	condition:
		any of ($a_*)
 
}