
rule Backdoor_BAT_Crysan_ADRA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ADRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 16 13 05 38 1e 00 00 00 09 11 04 11 05 08 11 05 59 6f ?? 00 00 0a 13 06 11 06 39 0c 00 00 00 11 05 11 06 58 13 05 11 05 08 32 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}