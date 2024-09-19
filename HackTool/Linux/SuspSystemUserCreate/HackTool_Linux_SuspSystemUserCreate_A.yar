
rule HackTool_Linux_SuspSystemUserCreate_A{
	meta:
		description = "HackTool:Linux/SuspSystemUserCreate.A,SIGNATURE_TYPE_CMDHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 00 73 00 65 00 72 00 61 00 64 00 64 00 } //10 useradd
		$a_00_1 = {2d 00 2d 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //10 --system
		$a_00_2 = {53 00 42 00 61 00 74 00 74 00 61 00 63 00 6b 00 65 00 72 00 } //5 SBattacker
		$a_00_3 = {53 00 42 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //5 SBUsername
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5) >=25
 
}