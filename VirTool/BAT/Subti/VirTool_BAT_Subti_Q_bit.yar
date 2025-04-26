
rule VirTool_BAT_Subti_Q_bit{
	meta:
		description = "VirTool:BAT/Subti.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 72 75 6e 6e 65 72 73 } //1 Antirunners
		$a_01_1 = {4e 61 74 69 76 65 46 75 6e 63 74 69 6f 6e 73 } //1 NativeFunctions
		$a_01_2 = {43 72 69 74 69 63 61 6c 50 72 6f 63 65 73 73 } //1 CriticalProcess
		$a_01_3 = {16 0a 2b 10 00 03 06 03 06 91 1f 20 61 d2 9c 00 06 17 58 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}