
rule Trojan_BAT_AgentTesla_BZQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 0d 09 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 09 6f 90 01 03 0a 00 73 90 01 03 0a 13 04 11 04 06 6f 90 01 03 0a 00 11 04 04 6f 90 01 03 0a 00 11 04 05 6f 90 01 03 0a 00 11 04 6f 90 01 03 0a 02 16 02 8e b7 6f 90 01 03 0a 0b 11 04 6f 90 01 03 0a 00 07 0c 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}