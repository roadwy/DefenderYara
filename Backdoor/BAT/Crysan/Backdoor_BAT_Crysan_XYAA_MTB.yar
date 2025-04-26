
rule Backdoor_BAT_Crysan_XYAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.XYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 de 07 2a 02 2b b7 28 ?? ?? 00 06 2b b2 0a 2b b6 06 2b b5 0b 2b bb 0c 2b bf 0d 2b c1 07 2b c2 09 2b c1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}