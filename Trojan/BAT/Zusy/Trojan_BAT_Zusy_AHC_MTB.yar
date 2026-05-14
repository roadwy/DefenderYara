
rule Trojan_BAT_Zusy_AHC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 0b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 0e 11 0e 28 ?? ?? ?? 06 13 0f 11 0f 1f 09 28 ?? ?? ?? 06 13 10 11 10 28 ?? ?? ?? 06 13 11 28 ?? ?? ?? 0a 11 11 6f ?? ?? ?? 0a 13 12 11 12 8e 69 28 ?? ?? ?? 0a 13 13 7e ?? ?? ?? 0a 2c 07 11 13 } //30
		$a_81_1 = {32 35 24 62 63 44 30 39 38 37 79 75 69 6f 32 35 } //20 25$bcD0987yuio25
	condition:
		((#a_03_0  & 1)*30+(#a_81_1  & 1)*20) >=50
 
}