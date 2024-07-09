
rule Trojan_BAT_AgentTesla_DAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 05 16 13 08 2b 18 11 05 11 08 11 04 11 08 9a 1f 10 28 ?? 00 00 0a d2 9c 11 08 17 58 13 08 11 08 11 04 8e 69 32 e0 } //3
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}