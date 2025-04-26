
rule Trojan_BAT_AgentTesla_SI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 17 58 13 04 07 11 04 07 8e 69 5d 91 13 05 08 09 1f 16 5d 91 13 06 07 09 91 11 06 61 13 07 07 09 11 07 11 05 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 07 8e 69 32 c2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}