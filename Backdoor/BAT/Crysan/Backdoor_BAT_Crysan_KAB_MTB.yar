
rule Backdoor_BAT_Crysan_KAB_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 09 06 09 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d d6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}