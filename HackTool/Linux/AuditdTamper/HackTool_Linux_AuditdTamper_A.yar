
rule HackTool_Linux_AuditdTamper_A{
	meta:
		description = "HackTool:Linux/AuditdTamper.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {61 00 75 00 64 00 69 00 74 00 63 00 74 00 6c 00 20 00 2d 00 65 00 30 00 } //0a 00 
		$a_00_1 = {61 00 75 00 64 00 69 00 74 00 63 00 74 00 6c 00 20 00 2d 00 65 00 20 00 30 00 } //0a 00 
		$a_00_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 61 00 75 00 64 00 69 00 74 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}