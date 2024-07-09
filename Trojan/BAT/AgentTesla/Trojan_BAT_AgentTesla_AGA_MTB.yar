
rule Trojan_BAT_AgentTesla_AGA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 8d ?? ?? ?? 01 0d 16 0a 2b 11 09 06 07 06 9a 1f 10 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 07 8e 69 fe 04 13 05 11 05 2d e3 } //2
		$a_01_1 = {53 00 54 00 4b 00 53 00 49 00 4d 00 55 00 4c 00 } //1 STKSIMUL
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}