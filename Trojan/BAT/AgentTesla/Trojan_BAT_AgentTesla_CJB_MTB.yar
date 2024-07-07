
rule Trojan_BAT_AgentTesla_CJB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 91 06 08 1f 10 5d 91 61 9c 08 17 d6 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}