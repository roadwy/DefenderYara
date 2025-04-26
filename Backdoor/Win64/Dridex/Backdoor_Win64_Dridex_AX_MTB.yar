
rule Backdoor_Win64_Dridex_AX_MTB{
	meta:
		description = "Backdoor:Win64/Dridex.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {44 73 52 65 70 6c 69 63 61 44 65 6c 57 } //DsReplicaDelW  3
		$a_80_1 = {44 73 46 72 65 65 50 61 73 73 77 6f 72 64 43 72 65 64 65 6e 74 69 61 6c 73 } //DsFreePasswordCredentials  3
		$a_80_2 = {42 2e 6f 6d 70 72 7a 79 } //B.omprzy  3
		$a_80_3 = {40 2e 63 76 6c } //@.cvl  3
		$a_80_4 = {46 6d 74 49 64 54 6f 50 72 6f 70 53 74 67 4e 61 6d 65 } //FmtIdToPropStgName  3
		$a_80_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //ShellExecuteExA  3
		$a_80_6 = {53 65 74 75 70 43 6f 6d 6d 69 74 46 69 6c 65 51 75 65 75 65 57 } //SetupCommitFileQueueW  3
		$a_80_7 = {53 65 74 75 70 51 75 65 72 79 53 70 61 63 65 52 65 71 75 69 72 65 64 4f 6e 44 72 69 76 65 57 } //SetupQuerySpaceRequiredOnDriveW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}