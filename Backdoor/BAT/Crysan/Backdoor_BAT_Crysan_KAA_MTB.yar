
rule Backdoor_BAT_Crysan_KAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 11 04 11 06 91 09 28 ?? 00 00 0a 59 d2 9c 11 06 17 58 13 06 11 06 11 04 8e 69 3f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}