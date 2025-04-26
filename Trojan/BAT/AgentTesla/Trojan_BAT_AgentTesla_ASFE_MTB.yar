
rule Trojan_BAT_AgentTesla_ASFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 09 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 28 ?? 00 00 06 28 ?? 00 00 0a 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 08 11 08 2d } //1
		$a_01_1 = {47 00 5a 00 42 00 35 00 53 00 34 00 41 00 47 00 38 00 5a 00 46 00 45 00 48 00 31 00 41 00 37 00 38 00 54 00 5a 00 48 00 35 00 5a 00 } //1 GZB5S4AG8ZFEH1A78TZH5Z
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}