
rule Trojan_BAT_AgentTesla_DNA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 6c 23 00 ba f4 ee 2a 81 f7 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 13 06 12 06 28 90 01 03 0a 13 05 07 11 05 6f 90 01 03 0a 26 00 09 17 d6 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}