
rule Trojan_BAT_AgentTesla_MVH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 07 8e 69 5d 11 0e 20 00 01 00 00 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}