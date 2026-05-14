
rule HackTool_BAT_Spammer_AMTB{
	meta:
		description = "HackTool:BAT/Spammer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 68 53 70 61 6d } //whSpam  1
		$a_80_1 = {4c 69 74 68 69 75 6d 53 68 61 72 65 64 } //LithiumShared  1
		$a_80_2 = {72 61 6e 20 62 79 20 6c 69 74 68 69 75 6d } //ran by lithium  1
		$a_80_3 = {44 69 73 63 6f 72 64 20 6e 75 6b 65 72 20 62 79 20 76 65 72 6c 6f 78 20 26 20 72 75 73 73 69 61 6e 20 68 65 61 76 79 } //Discord nuker by verlox & russian heavy  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}