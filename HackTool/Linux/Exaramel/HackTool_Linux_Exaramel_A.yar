
rule HackTool_Linux_Exaramel_A{
	meta:
		description = "HackTool:Linux/Exaramel.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {2e 53 65 74 75 70 42 65 61 63 6f 6e 49 6e 66 6f } //1 .SetupBeaconInfo
		$a_81_1 = {2e 65 78 65 63 53 68 65 6c 6c } //1 .execShell
		$a_81_2 = {2e 53 65 74 75 70 43 72 6f 6e 74 61 62 50 65 72 73 69 73 74 65 6e 63 65 } //1 .SetupCrontabPersistence
		$a_81_3 = {2e 53 65 74 75 70 53 79 73 74 65 6d 64 50 65 72 73 69 73 74 65 6e 63 65 } //1 .SetupSystemdPersistence
		$a_81_4 = {6e 65 74 77 6f 72 6b 65 72 2e 53 65 6e 64 52 65 70 6f 72 74 } //1 networker.SendReport
		$a_81_5 = {77 6f 72 6b 65 72 2e 4f 53 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 worker.OSShellExecute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}