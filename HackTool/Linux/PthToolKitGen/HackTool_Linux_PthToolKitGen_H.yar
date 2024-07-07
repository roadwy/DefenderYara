
rule HackTool_Linux_PthToolKitGen_H{
	meta:
		description = "HackTool:Linux/PthToolKitGen.H,SIGNATURE_TYPE_CMDHSTR_EXT,3c 00 3c 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //10 python
		$a_02_1 = {2d 00 68 00 61 00 73 00 68 00 65 00 73 00 20 00 90 2f 40 00 3a 00 90 00 } //50
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*50) >=60
 
}