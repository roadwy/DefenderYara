
rule Trojan_BAT_AgentTesla_FAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0b 2b 19 08 06 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 07 18 58 0b 07 06 6f ?? 00 00 0a 32 de } //3
		$a_01_1 = {77 61 74 65 72 77 68 65 65 6c 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 waterwheel1.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}