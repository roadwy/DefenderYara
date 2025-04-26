
rule Backdoor_BAT_Crysan_PWAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.PWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 14 0b 28 ?? 00 00 06 0b 06 07 6f ?? 00 00 0a 28 ?? 00 00 0a 06 16 6f ?? 00 00 0a 6f ?? 00 00 0a 0c } //1
		$a_03_1 = {09 08 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 18 58 13 04 11 04 08 6f ?? 00 00 0a 32 da 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 06 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}