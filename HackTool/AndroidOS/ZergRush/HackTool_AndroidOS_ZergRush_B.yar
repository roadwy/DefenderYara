
rule HackTool_AndroidOS_ZergRush_B{
	meta:
		description = "HackTool:AndroidOS/ZergRush.B,SIGNATURE_TYPE_ELFHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 6f 6f 6d 73 68 00 } //1 戯潯獭h
		$a_01_1 = {2f 7a 7a 7a 7a 73 68 00 } //1 稯空獺h
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 76 6f 6c 64 00 } //10
		$a_00_3 = {41 6e 64 72 6f 69 64 20 32 2e 32 2f 32 2e 33 20 6c 6f 63 61 6c 20 72 6f 6f 74 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10) >=21
 
}