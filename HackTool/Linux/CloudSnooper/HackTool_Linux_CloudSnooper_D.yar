
rule HackTool_Linux_CloudSnooper_D{
	meta:
		description = "HackTool:Linux/CloudSnooper.D,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {72 00 72 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 2d 00 64 00 } //05 00 
		$a_00_1 = {72 00 72 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 2d 00 73 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}