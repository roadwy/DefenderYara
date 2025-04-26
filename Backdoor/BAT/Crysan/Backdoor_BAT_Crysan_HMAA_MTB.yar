
rule Backdoor_BAT_Crysan_HMAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.HMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 09 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 } //3
		$a_03_1 = {13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 11 06 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}