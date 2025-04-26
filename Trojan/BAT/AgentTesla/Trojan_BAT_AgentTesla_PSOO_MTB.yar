
rule Trojan_BAT_AgentTesla_PSOO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 00 07 18 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 06 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 03 16 03 8e 69 6f ?? ?? ?? 0a 0c de 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}