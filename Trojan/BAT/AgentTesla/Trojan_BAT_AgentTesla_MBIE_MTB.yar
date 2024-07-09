
rule Trojan_BAT_AgentTesla_MBIE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 91 06 09 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 32 } //1
		$a_03_1 = {20 76 83 00 00 28 ?? 00 00 06 0a 14 0b 28 ?? 00 00 06 0b 07 8e 69 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}