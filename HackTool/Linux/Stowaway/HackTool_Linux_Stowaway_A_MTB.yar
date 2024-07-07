
rule HackTool_Linux_Stowaway_A_MTB{
	meta:
		description = "HackTool:Linux/Stowaway.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 6f 77 61 77 61 79 2f 73 68 61 72 65 } //10 Stowaway/share
		$a_01_1 = {53 74 6f 77 61 77 61 79 2f 61 67 65 6e 74 } //10 Stowaway/agent
		$a_01_2 = {72 75 6e 74 69 6d 65 2e 69 6e 6a 65 63 74 67 6c 69 73 74 } //1 runtime.injectglist
		$a_01_3 = {63 61 6e 57 72 69 74 65 52 65 63 6f 72 64 } //1 canWriteRecord
		$a_01_4 = {64 69 72 74 79 4c 6f 63 6b 65 64 } //1 dirtyLocked
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}