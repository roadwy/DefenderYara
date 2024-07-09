
rule HackTool_Linux_Linikatz_E{
	meta:
		description = "HackTool:Linux/Linikatz.E,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 00 67 00 72 00 65 00 70 00 } //5 egrep
		$a_00_1 = {6c 00 69 00 62 00 6b 00 72 00 62 00 35 00 } //1 libkrb5
		$a_00_2 = {6c 00 69 00 62 00 6c 00 64 00 61 00 70 00 } //1 libldap
		$a_02_3 = {2f 00 70 00 72 00 6f 00 63 00 2f 00 90 29 05 00 2f 00 6d 00 61 00 70 00 73 00 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*5) >=11
 
}