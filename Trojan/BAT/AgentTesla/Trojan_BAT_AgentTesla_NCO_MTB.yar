
rule Trojan_BAT_AgentTesla_NCO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0c 13 09 38 1f ff ff ff } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}