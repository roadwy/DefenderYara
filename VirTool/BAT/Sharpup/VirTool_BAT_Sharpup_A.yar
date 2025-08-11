
rule VirTool_BAT_Sharpup_A{
	meta:
		description = "VirTool:BAT/Sharpup.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {48 69 6a 61 63 6b 61 62 6c 65 50 61 74 68 73 } //1 HijackablePaths
		$a_81_1 = {50 72 69 76 65 73 63 43 68 65 63 6b 73 } //1 PrivescChecks
		$a_81_2 = {76 75 6c 6e 65 72 61 62 6c 65 43 68 65 63 6b 73 } //1 vulnerableChecks
		$a_81_3 = {54 6f 6b 65 6e 47 72 6f 75 70 73 41 6e 64 50 72 69 76 69 6c 65 67 65 73 } //1 TokenGroupsAndPrivileges
		$a_81_4 = {4d 6f 64 69 66 69 61 62 6c 65 53 65 72 76 69 63 65 42 69 6e 61 72 69 65 73 } //1 ModifiableServiceBinaries
		$a_81_5 = {47 65 74 52 65 67 56 61 6c 75 65 73 } //1 GetRegValues
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}