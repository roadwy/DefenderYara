
rule Backdoor_BAT_Bladabindi_ABJA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ABJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 1a 58 4a 02 8e 69 5d 1f 67 59 1f 67 58 02 06 1a 58 4a 02 8e 69 5d 1e 58 1f 15 58 1f 1d 59 91 07 06 1a 58 4a 07 8e 69 5d 1d 58 1f 0d 58 1f 15 59 1f 17 58 1f 16 59 91 61 02 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 02 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}