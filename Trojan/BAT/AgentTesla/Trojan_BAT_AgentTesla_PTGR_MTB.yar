
rule Trojan_BAT_AgentTesla_PTGR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 0c 00 00 04 03 58 7d 0c 00 00 04 20 00 00 00 00 7e 1d 00 00 04 7b 19 00 00 04 3a cc ff ff ff 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}