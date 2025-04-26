
rule Trojan_BAT_AgentTesla_ABIM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 90 0a 3b 00 02 73 ?? ?? ?? 0a 16 73 ?? ?? ?? 0a 0a 00 20 ?? ?? ?? 00 8d ?? ?? ?? 01 0b 00 00 73 ?? ?? ?? 0a 0c } //4
		$a_01_1 = {46 00 69 00 62 00 6f 00 6e 00 61 00 63 00 63 00 69 00 43 00 6c 00 6f 00 63 00 6b 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 FibonacciClock.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}