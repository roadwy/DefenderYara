
rule Trojan_BAT_AgentTesla_EPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 06 20 00 5c 00 00 5d 11 01 11 06 20 00 5c 00 00 5d 91 11 02 11 06 1f 16 5d ?? ?? ?? ?? ?? 61 11 01 11 06 17 58 20 00 5c 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}