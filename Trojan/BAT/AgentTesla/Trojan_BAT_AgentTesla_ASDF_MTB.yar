
rule Trojan_BAT_AgentTesla_ASDF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 07 09 17 58 07 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 00 00 0a 9c 09 15 58 0d 09 16 2f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}