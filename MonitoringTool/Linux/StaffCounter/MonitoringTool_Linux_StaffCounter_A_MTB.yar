
rule MonitoringTool_Linux_StaffCounter_A_MTB{
	meta:
		description = "MonitoringTool:Linux/StaffCounter.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 73 75 6d 65 20 6d 6f 6e 69 74 6f 72 69 6e 67 } //01 00  resume monitoring
		$a_00_1 = {73 63 72 65 65 6e 73 68 6f 74 73 2f } //01 00  screenshots/
		$a_00_2 = {2f 74 6d 70 2f 6b 65 79 73 2e 6c 6f 67 } //01 00  /tmp/keys.log
		$a_00_3 = {73 65 74 74 69 6e 67 73 2f 6b 65 79 73 74 72 6f 6b 65 73 } //01 00  settings/keystrokes
		$a_00_4 = {2f 6c 6f 67 73 2f 73 65 6e 74 } //01 00  /logs/sent
		$a_00_5 = {2f 73 74 61 66 66 63 6f 75 6e 74 65 72 2e 6c 6f 67 } //00 00  /staffcounter.log
	condition:
		any of ($a_*)
 
}