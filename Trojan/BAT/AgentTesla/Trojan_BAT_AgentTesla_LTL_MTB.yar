
rule Trojan_BAT_AgentTesla_LTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {72 31 63 33 72 73 74 72 69 6d 2f 77 61 72 2f 74 65 6e 2e 6e 69 62 74 78 65 74 2f 2f 3a 73 70 74 74 68 } //1 r1c3rstrim/war/ten.nibtxet//:sptth
		$a_81_1 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {53 70 6c 69 74 } //1 Split
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}