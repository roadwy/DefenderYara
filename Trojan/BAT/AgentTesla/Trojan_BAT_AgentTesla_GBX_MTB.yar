
rule Trojan_BAT_AgentTesla_GBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}