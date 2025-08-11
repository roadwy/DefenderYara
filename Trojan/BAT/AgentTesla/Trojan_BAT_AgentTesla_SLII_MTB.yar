
rule Trojan_BAT_AgentTesla_SLII_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SLII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 56 00 00 0a 2a 28 60 00 00 0a (25 26|) 7e 12 00 00 04 02 06 6f 5c 00 00 0a 0b 07 28 61 00 00 0a 25 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}