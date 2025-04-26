
rule Backdoor_BAT_Crysan_HIAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.HIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 06 6f ?? 00 00 0a 1f 10 6a 59 17 6a 58 d4 8d ?? 00 00 01 13 08 11 07 11 08 16 11 08 8e 69 6f ?? 00 00 0a 8d ?? 00 00 01 13 09 11 08 16 11 09 16 11 09 8e 69 28 ?? 00 00 0a 11 09 13 05 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}