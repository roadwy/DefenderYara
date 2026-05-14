
rule Trojan_BAT_AgentTesla_GPAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 06 61 13 10 08 11 0a 11 10 20 ff 00 00 00 5f d2 9c 08 11 0a 17 58 11 10 } //5
		$a_81_1 = {50 72 6f 63 65 73 73 48 6f 6c 6c 6f 77 69 6e 67 } //1 ProcessHollowing
		$a_81_2 = {74 61 72 67 65 74 50 72 6f 63 65 73 73 50 61 74 68 } //1 targetProcessPath
		$a_81_3 = {70 61 79 6c 6f 61 64 } //1 payload
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=8
 
}