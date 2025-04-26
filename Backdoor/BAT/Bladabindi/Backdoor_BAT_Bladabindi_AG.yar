
rule Backdoor_BAT_Bladabindi_AG{
	meta:
		description = "Backdoor:BAT/Bladabindi.AG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4c 6f 67 67 65 72 } //1 KeyLogger
		$a_01_1 = {73 74 61 72 74 75 70 66 69 78 65 64 52 } //1 startupfixedR
		$a_01_2 = {25 00 76 00 6e 00 25 00 } //1 %vn%
		$a_01_3 = {30 00 2e 00 35 00 2e 00 35 00 } //1 0.5.5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}