
rule Trojan_BAT_AgentTesla_ABE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 95 2e 03 16 2b 01 17 17 59 7e 02 00 00 04 20 33 09 00 00 07 0b 95 5f 7e 02 00 00 04 07 0b 20 d6 0e 00 00 95 61 59 80 1a 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}