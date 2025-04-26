
rule Trojan_BAT_AgentTesla_MBZR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 08 11 ?? 1f ?? 5d 6f ?? ?? ?? 0a 61 13 ?? 11 ?? 11 ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}