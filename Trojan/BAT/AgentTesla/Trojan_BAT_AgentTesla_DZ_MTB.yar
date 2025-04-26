
rule Trojan_BAT_AgentTesla_DZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 02 08 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d da } //1
		$a_03_1 = {06 0b 07 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f 18 01 00 0a 0c 08 28 9d 00 00 06 0d 28 19 01 00 0a 09 6f 1a 01 00 0a 13 04 11 04 6f 1b 01 00 0a 16 9a 13 05 11 05 14 72 ?? ?? ?? 70 17 8d 11 00 00 01 25 16 72 ?? ?? ?? 70 a2 14 14 28 1c 01 00 0a 13 06 11 06 14 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}