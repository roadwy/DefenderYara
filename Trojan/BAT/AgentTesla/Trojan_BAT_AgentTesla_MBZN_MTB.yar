
rule Trojan_BAT_AgentTesla_MBZN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 8e 69 5d 02 06 07 06 8e 69 5d 91 09 07 09 6f ?? 01 00 0a 5d 6f ?? 01 00 0a 61 28 ?? 01 00 0a 06 07 17 58 06 8e 69 5d 91 28 ?? 01 00 0a 59 20 00 01 00 00 58 28 ?? 00 00 06 28 ?? 01 00 0a 9c 07 15 58 0b } //1
		$a_01_1 = {53 77 69 74 63 68 62 6f 61 72 64 53 65 72 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SwitchboardServer.Properties
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}