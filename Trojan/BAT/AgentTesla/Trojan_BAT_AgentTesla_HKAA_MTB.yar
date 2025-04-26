
rule Trojan_BAT_AgentTesla_HKAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 06 8e 69 8d 64 00 00 01 0c 16 0d 2b 15 00 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d df } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}