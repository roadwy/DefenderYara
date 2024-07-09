
rule Trojan_BAT_AgentTesla_DAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 07 2b 18 00 09 11 07 08 11 07 9a 1f 10 28 ?? 00 00 0a d2 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d db } //3
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}