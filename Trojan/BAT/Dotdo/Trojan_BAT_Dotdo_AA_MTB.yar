
rule Trojan_BAT_Dotdo_AA_MTB{
	meta:
		description = "Trojan:BAT/Dotdo.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {15 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 01 00 00 00 04 00 00 00 02 } //10
		$a_81_1 = {5c 74 72 79 5c 74 72 79 5c } //3 \try\try\
		$a_81_2 = {61 70 70 2e 70 64 62 } //3 app.pdb
		$a_81_3 = {61 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //3 app.Properties.Resources
		$a_81_4 = {44 6f 63 6b 53 74 79 6c 65 } //3 DockStyle
		$a_81_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //3 DebuggingModes
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=25
 
}