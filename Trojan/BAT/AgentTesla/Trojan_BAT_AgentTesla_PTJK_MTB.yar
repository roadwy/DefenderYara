
rule Trojan_BAT_AgentTesla_PTJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 1f 16 6a 5d 13 0b 07 11 08 07 11 08 91 09 11 0b d4 91 61 28 ?? 00 00 0a 07 11 09 08 6a 5d d4 91 28 ?? 00 00 0a 59 11 0a 58 11 0a 5d 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}