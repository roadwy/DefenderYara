
rule HackTool_Linux_Ddexec_FZ2{
	meta:
		description = "HackTool:Linux/Ddexec.FZ2,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 00 64 00 65 00 78 00 65 00 63 00 2e 00 73 00 68 00 } //1 ddexec.sh
		$a_00_1 = {44 00 44 00 65 00 78 00 65 00 63 00 2e 00 67 00 69 00 74 00 } //1 DDexec.git
		$a_02_2 = {67 00 69 00 74 00 68 00 75 00 62 00 [0-50] 2f 00 44 00 44 00 65 00 78 00 65 00 63 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}