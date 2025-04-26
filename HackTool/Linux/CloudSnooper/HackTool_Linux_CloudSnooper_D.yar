
rule HackTool_Linux_CloudSnooper_D{
	meta:
		description = "HackTool:Linux/CloudSnooper.D,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 72 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 2d 00 64 00 } //5 rrtserver -d
		$a_00_1 = {72 00 72 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 2d 00 73 00 20 00 } //5 rrtserver -s 
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5) >=5
 
}