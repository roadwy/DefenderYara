
rule Trojan_BAT_AgentTesla_ALK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 09 91 13 0b 11 08 17 58 08 5d 13 0c 07 11 08 91 11 0b 61 07 11 0c 91 59 13 0d 11 0d 20 00 01 00 00 58 13 0e 07 11 08 11 0e 20 ff 00 00 00 5f d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}