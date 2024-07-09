
rule Trojan_BAT_AgentTesla_GAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 1f 16 13 20 2b 25 11 1e 11 20 18 6f ?? 00 00 0a 20 ?? 02 00 00 28 ?? 00 00 0a 13 22 11 1f 11 22 6f ?? 00 00 0a 11 20 18 58 13 20 11 20 11 1e 6f ?? 00 00 0a fe 04 2d ce } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}