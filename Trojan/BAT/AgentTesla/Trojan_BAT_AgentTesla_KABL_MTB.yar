
rule Trojan_BAT_AgentTesla_KABL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 13 0c 11 0c 08 11 08 1f 16 5d 91 61 13 0d 11 0d 11 0b 59 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0f 11 0f 2d a6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}