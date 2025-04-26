
rule Trojan_BAT_Bladabindi_DNGM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DNGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 72 0d 00 00 70 15 16 28 ?? ?? ?? 0a 0c 00 08 8e 69 17 da 17 d6 8d 2a 00 00 01 0d 08 8e 69 18 da 13 04 16 13 05 2b 15 00 09 11 05 08 11 05 9a 28 ?? ?? ?? 0a 9c 00 11 05 17 d6 13 05 11 05 11 04 fe 02 16 fe 01 13 06 11 06 2d dc 09 13 07 2b 00 11 07 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}