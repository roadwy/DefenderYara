
rule Trojan_BAT_AgentTesla_MBZZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 ?? 09 5d 91 59 20 00 01 00 00 58 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}