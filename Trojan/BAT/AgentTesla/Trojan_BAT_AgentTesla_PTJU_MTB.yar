
rule Trojan_BAT_AgentTesla_PTJU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8c 42 00 00 01 a2 28 ?? 00 00 0a 13 0d 02 11 0d 28 ?? 00 00 06 13 0e 72 df 01 00 70 28 ?? 00 00 06 1f 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}