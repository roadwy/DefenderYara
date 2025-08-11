
rule HackTool_Linux_PenteraPayload_A{
	meta:
		description = "HackTool:Linux/PenteraPayload.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 63 74 69 6f 6e 73 2e 44 42 53 65 72 76 69 63 65 54 65 72 6d 69 6e 61 74 69 6f 6e 41 63 74 69 6f 6e 2e 47 65 74 4f 73 43 6f 6d 6d 61 6e 64 73 } //Actions.DBServiceTerminationAction.GetOsCommands  1
		$a_80_1 = {41 63 74 69 6f 6e 73 2e 42 61 63 6b 75 70 53 65 72 76 69 63 65 54 65 72 6d 69 6e 61 74 69 6f 6e 41 63 74 69 6f 6e 2e 47 65 74 4f 73 43 6f 6d 6d 61 6e 64 73 } //Actions.BackupServiceTerminationAction.GetOsCommands  1
		$a_80_2 = {41 63 74 69 6f 6e 73 2e 45 44 52 53 65 72 76 69 63 65 54 65 72 6d 69 6e 61 74 69 6f 6e 41 63 74 69 6f 6e 2e 47 65 74 4f 73 43 6f 6d 6d 61 6e 64 73 } //Actions.EDRServiceTerminationAction.GetOsCommands  1
		$a_80_3 = {41 63 74 69 6f 6e 73 2e 46 69 6c 65 73 45 6e 63 72 79 70 74 69 6f 6e 41 63 74 69 6f 6e 2e 45 6e 63 72 79 70 74 46 69 6c 65 } //Actions.FilesEncryptionAction.EncryptFile  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}