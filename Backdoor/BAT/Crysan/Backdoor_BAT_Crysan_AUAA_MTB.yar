
rule Backdoor_BAT_Crysan_AUAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 0c 00 11 0c 11 06 17 73 ?? 00 00 0a 13 0d 11 0d 02 16 02 8e 69 6f ?? 00 00 0a 00 11 0d 6f ?? 00 00 0a 00 de 0e 00 11 0d 2c 08 11 0d 6f ?? 00 00 0a 00 dc 11 0c 6f ?? 00 00 0a 0a de 21 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}