
rule Trojan_BAT_AgentTesla_UNk_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UNk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0a 91 11 07 58 13 0d 07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c 00 11 06 17 58 13 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}