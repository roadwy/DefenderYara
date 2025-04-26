
rule HackTool_Win32_StopDef_A{
	meta:
		description = "HackTool:Win32/StopDef.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 74 6f 70 44 65 66 65 6e 64 65 72 2e 70 64 62 } //StopDefender.pdb  1
		$a_80_1 = {54 52 55 53 54 45 44 49 4e 53 54 41 4c 4c 45 52 20 53 74 6f 70 44 65 66 65 6e 64 65 72 53 65 72 76 69 63 65 28 29 20 73 75 63 63 65 73 73 } //TRUSTEDINSTALLER StopDefenderService() success  1
		$a_80_2 = {54 52 55 53 54 45 44 49 4e 53 54 41 4c 4c 45 52 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 4c 6f 67 67 65 64 4f 6e 55 73 65 72 28 29 20 73 75 63 63 65 73 73 } //TRUSTEDINSTALLER ImpersonatedLoggedOnUser() success  1
		$a_80_3 = {57 69 6e 6c 6f 67 6f 6e 20 70 72 6f 63 65 73 73 20 6e 6f 74 20 66 6f 75 6e 64 } //Winlogon process not found  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}