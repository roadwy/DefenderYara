
rule HackTool_Linux_SuspPrivilegeEscalation_A{
	meta:
		description = "HackTool:Linux/SuspPrivilegeEscalation.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 68 00 6d 00 6f 00 64 00 20 00 67 00 2b 00 73 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 61 00 69 00 71 00 2d 00 } //10 chmod g+s /tmp/aiq-
	condition:
		((#a_00_0  & 1)*10) >=10
 
}