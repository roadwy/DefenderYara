
rule HackTool_Linux_PenteraPayload_B{
	meta:
		description = "HackTool:Linux/PenteraPayload.B,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 63 74 69 6f 6e 73 2f 42 61 63 6b 75 70 53 65 72 76 69 63 65 54 65 72 6d 69 6e 61 74 69 6f 6e 41 63 74 69 6f 6e 2e 67 6f } //Actions/BackupServiceTerminationAction.go  1
		$a_80_1 = {41 63 74 69 6f 6e 73 2f 44 42 53 65 72 76 69 63 65 54 65 72 6d 69 6e 61 74 69 6f 6e 41 63 74 69 6f 6e 2e 67 6f } //Actions/DBServiceTerminationAction.go  1
		$a_80_2 = {41 63 74 69 6f 6e 73 2f 45 44 52 54 65 72 6d 69 6e 61 74 69 6f 6e 41 63 74 69 6f 6e 2e 67 6f } //Actions/EDRTerminationAction.go  1
		$a_80_3 = {41 63 74 69 6f 6e 73 2f 53 65 6e 64 49 6e 6a 65 63 74 65 64 53 74 72 69 6e 67 73 41 63 74 69 6f 6e 2e 67 6f } //Actions/SendInjectedStringsAction.go  1
		$a_80_4 = {41 63 74 69 6f 6e 73 2f 46 69 6c 65 73 45 6e 63 72 79 70 74 69 6f 6e 41 63 74 69 6f 6e 2e 67 6f } //Actions/FilesEncryptionAction.go  1
		$a_80_5 = {41 63 74 69 6f 6e 73 2f 4f 73 43 6f 6d 6d 61 6e 64 73 41 63 74 69 6f 6e 2e 67 6f } //Actions/OsCommandsAction.go  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}