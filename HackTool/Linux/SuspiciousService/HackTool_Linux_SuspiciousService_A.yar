
rule HackTool_Linux_SuspiciousService_A{
	meta:
		description = "HackTool:Linux/SuspiciousService.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 20 00 53 00 42 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //0a 00  systemctl enable SBService
		$a_00_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 53 00 42 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //00 00  systemctl start SBService
	condition:
		any of ($a_*)
 
}