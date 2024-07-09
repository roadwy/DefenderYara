
rule Trojan_BAT_AgentTesla_FAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 06 72 ?? 06 00 70 6f ?? 00 00 0a 74 04 00 00 1b 6f ?? 00 00 0a 00 06 72 ?? 06 00 70 6f ?? 00 00 0a 74 04 00 00 1b 0c 06 72 ?? 06 00 70 6f ?? 00 00 0a 74 04 00 00 1b 0d 08 28 ?? 00 00 0a 00 09 28 ?? 00 00 0a 00 07 08 6f ?? 00 00 0a 00 07 09 6f ?? 00 00 0a 00 07 06 72 ?? 06 00 70 6f } //3
		$a_01_1 = {43 00 6f 00 72 00 65 00 43 00 4c 00 49 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 CoreCLI.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}