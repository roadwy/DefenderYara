
rule Trojan_BAT_AgentTesla_MBFG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 1f 16 5d 91 61 13 0d 11 0d 11 0b 59 13 0e 07 11 05 11 0e 20 00 01 00 00 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}