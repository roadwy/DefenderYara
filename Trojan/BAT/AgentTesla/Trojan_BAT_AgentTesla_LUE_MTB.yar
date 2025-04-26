
rule Trojan_BAT_AgentTesla_LUE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 2c 00 08 09 11 04 28 ?? ?? ?? 06 13 08 11 08 28 ?? ?? ?? 0a 13 09 07 09 11 09 d2 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d c9 } //1
		$a_01_1 = {45 33 35 34 32 33 34 35 33 34 36 } //1 E3542345346
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}