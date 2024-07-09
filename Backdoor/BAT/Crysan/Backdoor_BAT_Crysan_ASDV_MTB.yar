
rule Backdoor_BAT_Crysan_ASDV_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ASDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? 01 00 06 03 06 1a 58 4a 1c 58 1b 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 03 8e 69 17 59 16 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}