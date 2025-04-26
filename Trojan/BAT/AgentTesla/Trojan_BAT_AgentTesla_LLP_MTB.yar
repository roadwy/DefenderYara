
rule Trojan_BAT_AgentTesla_LLP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0b 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0b 06 07 16 07 8e 69 6f ?? ?? ?? 0a 06 0c de 0a } //1
		$a_01_1 = {65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 } //1 edom SOD ni nur eb tonnac
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}