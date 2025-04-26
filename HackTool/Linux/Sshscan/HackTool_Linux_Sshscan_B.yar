
rule HackTool_Linux_Sshscan_B{
	meta:
		description = "HackTool:Linux/Sshscan.B,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 72 65 6d 6f 74 65 52 75 6e } //1 main.remoteRun
		$a_81_1 = {6d 61 69 6e 2e 6d 61 69 6e 2e 66 75 6e 63 31 } //1 main.main.func1
		$a_81_2 = {6d 61 69 6e 2e 72 65 6d 6f 74 65 52 75 6e 2e 66 75 6e 63 31 } //1 main.remoteRun.func1
		$a_81_3 = {6d 61 69 6e 2e 67 65 6e 65 72 61 74 65 49 50 73 52 61 6e 67 65 } //1 main.generateIPsRange
		$a_81_4 = {6d 61 69 6e 2e 69 70 41 66 74 65 72 } //1 main.ipAfter
		$a_81_5 = {6d 61 69 6e 2e 6e 65 78 74 49 50 } //1 main.nextIP
		$a_81_6 = {6d 61 69 6e 2e 73 65 74 75 70 43 72 6f 6e 4a 6f 62 73 } //1 main.setupCronJobs
		$a_81_7 = {6d 61 69 6e 2e 66 65 74 63 68 41 6e 64 53 61 76 65 } //1 main.fetchAndSave
		$a_81_8 = {6d 61 69 6e 2e 63 72 65 61 74 65 50 72 6f 74 6f 63 6f 6c 73 46 69 6c 65 49 66 4e 6f 74 45 78 69 73 74 73 } //1 main.createProtocolsFileIfNotExists
		$a_81_9 = {6d 61 69 6e 2e 65 78 65 63 43 6f 6d 6d 61 6e 64 } //1 main.execCommand
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=6
 
}