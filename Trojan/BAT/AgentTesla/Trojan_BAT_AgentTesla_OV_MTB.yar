
rule Trojan_BAT_AgentTesla_OV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 6f [0-04] 28 [0-04] 28 [0-04] 04 07 6f [0-04] 28 [0-04] 6a 61 b7 28 [0-08] 28 [0-09] 6f [0-04] 26 07 04 6f [0-04] 17 } //1
		$a_81_1 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_2 = {43 6f 6e 63 61 74 } //1 Concat
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}