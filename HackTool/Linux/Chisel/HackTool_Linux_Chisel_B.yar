
rule HackTool_Linux_Chisel_B{
	meta:
		description = "HackTool:Linux/Chisel.B,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 00 68 00 69 00 73 00 65 00 6c 00 [0-40] 20 00 73 00 65 00 72 00 76 00 65 00 72 00 } //10
		$a_02_1 = {63 00 68 00 69 00 73 00 65 00 6c 00 [0-40] 20 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}