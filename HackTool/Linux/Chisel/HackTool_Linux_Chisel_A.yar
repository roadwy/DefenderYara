
rule HackTool_Linux_Chisel_A{
	meta:
		description = "HackTool:Linux/Chisel.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 68 00 69 00 73 00 65 00 6c 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 } //10 chisel server
		$a_00_1 = {63 00 68 00 69 00 73 00 65 00 6c 00 20 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //10 chisel client
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}