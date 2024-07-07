
rule Trojan_BAT_AgentTesla_BWK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 17 58 0d 09 20 00 01 00 00 5d 0d 08 07 09 94 58 0c 08 20 00 01 00 00 5d 0c 07 09 94 90 02 02 07 09 07 08 94 9e 07 08 90 02 02 9e 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}