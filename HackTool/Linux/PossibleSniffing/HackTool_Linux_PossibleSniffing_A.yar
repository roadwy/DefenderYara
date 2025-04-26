
rule HackTool_Linux_PossibleSniffing_A{
	meta:
		description = "HackTool:Linux/PossibleSniffing.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {20 00 2d 00 69 00 } //5  -i
		$a_00_1 = {70 00 6f 00 72 00 74 00 20 00 32 00 31 00 20 00 6f 00 72 00 20 00 70 00 6f 00 72 00 74 00 20 00 32 00 33 00 } //1 port 21 or port 23
		$a_00_2 = {70 00 6f 00 72 00 74 00 20 00 32 00 33 00 20 00 6f 00 72 00 20 00 70 00 6f 00 72 00 74 00 20 00 32 00 31 00 } //1 port 23 or port 21
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}