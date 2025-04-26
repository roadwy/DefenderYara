
rule Backdoor_BAT_Crysan_AAUZ_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 72 ?? 00 00 70 73 ?? 00 00 0a 13 08 11 07 11 08 6f ?? 00 00 0a 13 09 1a 8d ?? 00 00 01 25 16 72 ?? 01 00 70 a2 25 17 7e ?? 00 00 0a a2 25 18 11 09 a2 25 19 17 8c ?? 00 00 01 a2 13 0a 14 13 0b 07 28 ?? 00 00 0a 13 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}