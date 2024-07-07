
rule Trojan_BAT_AgentTesla_JYB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 0c 07 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 0d 06 09 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 02 03 28 90 01 03 06 13 04 28 90 01 03 0a 06 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0c 08 13 05 2b 00 11 05 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}