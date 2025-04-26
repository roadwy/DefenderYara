
rule Backdoor_BAT_Crysan_IMAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.IMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 0c 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 0d 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 0f 00 00 00 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}