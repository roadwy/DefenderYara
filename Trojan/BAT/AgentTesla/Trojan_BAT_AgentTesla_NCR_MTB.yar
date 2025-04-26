
rule Trojan_BAT_AgentTesla_NCR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 a3 05 00 00 1b 13 04 11 04 16 06 07 11 04 8e 69 28 1b 00 00 0a 07 11 04 8e 69 58 0b 09 17 58 0d 09 08 8e 69 32 d8 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}