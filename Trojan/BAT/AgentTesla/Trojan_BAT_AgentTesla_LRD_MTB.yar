
rule Trojan_BAT_AgentTesla_LRD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 06 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 02 28 ?? ?? ?? 06 0c 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 00 08 0d 2b } //1
		$a_01_1 = {32 63 34 65 66 31 32 2d 34 63 65 65 2d 34 38 33 65 2d 39 32 34 62 2d 38 38 30 65 34 } //1 2c4ef12-4cee-483e-924b-880e4
		$a_01_2 = {00 58 58 58 58 58 58 58 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}