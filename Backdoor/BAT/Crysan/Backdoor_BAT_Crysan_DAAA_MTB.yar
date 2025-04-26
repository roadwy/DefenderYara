
rule Backdoor_BAT_Crysan_DAAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.DAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 13 06 11 06 16 1f 0a 9d 11 06 6f ?? 00 00 0a 0b 90 0a 27 00 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a 17 8d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}