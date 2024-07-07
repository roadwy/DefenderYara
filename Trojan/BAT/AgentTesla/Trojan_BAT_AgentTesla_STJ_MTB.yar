
rule Trojan_BAT_AgentTesla_STJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.STJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 0c 2b 4b 11 05 08 91 13 08 07 17 58 06 8e 69 5d 13 09 06 11 09 91 13 0a 11 04 07 11 04 90 01 05 5d 90 01 05 13 0b 11 08 11 0b 61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 06 07 11 0c d2 9c 07 17 58 0b 08 17 58 0c 08 11 05 8e 69 32 ae 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}