
rule Trojan_BAT_AgentTesla_MBZE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 28 ?? ?? ?? ?? 06 07 17 58 06 8e 69 5d 91 28 ?? ?? ?? ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? ?? 9c 07 15 58 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}