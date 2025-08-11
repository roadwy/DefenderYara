
rule Backdoor_BAT_Remcos_AROA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.AROA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 03 11 05 91 08 61 06 11 04 91 61 b4 9c 11 04 7e ?? 01 00 04 02 28 ?? 01 00 06 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 c8 7e ?? 02 00 04 09 74 ?? 00 00 01 03 8e b7 18 da 17 d6 8d ?? 00 00 01 28 ?? 02 00 06 74 ?? 00 00 1b 0d 09 13 07 de 65 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}