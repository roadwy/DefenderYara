
rule Trojan_BAT_AgentTesla_PTCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 87 ff ff ff 12 01 7c 0b 00 00 04 12 01 28 ?? 00 00 2b 20 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}