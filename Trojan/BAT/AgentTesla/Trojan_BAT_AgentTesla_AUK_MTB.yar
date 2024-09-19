
rule Trojan_BAT_AgentTesla_AUK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 91 04 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}