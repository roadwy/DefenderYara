
rule Backdoor_BAT_Crysan_AAZH_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 18 2c d9 17 58 16 2d 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}