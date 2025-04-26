
rule Trojan_BAT_Bladabindi_MBBM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2c 46 06 07 28 ?? 00 00 0a 72 11 e6 01 70 02 18 8c ?? 00 00 01 07 28 ?? 00 00 0a 17 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a b4 9c 07 08 12 01 28 ?? 00 00 0a 2d ba } //1
		$a_01_1 = {32 00 32 00 41 00 32 00 43 00 36 00 45 00 41 00 46 00 38 00 30 00 44 00 46 00 43 00 38 00 46 00 44 00 38 00 44 00 38 00 41 00 32 00 } //1 22A2C6EAF80DFC8FD8D8A2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}