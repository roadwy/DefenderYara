
rule HackTool_Linux_Linikatz_B{
	meta:
		description = "HackTool:Linux/Linikatz.B,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 00 74 00 72 00 69 00 6e 00 67 00 73 00 20 00 6c 00 69 00 6e 00 69 00 6b 00 61 00 74 00 7a 00 2e 00 90 29 05 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}