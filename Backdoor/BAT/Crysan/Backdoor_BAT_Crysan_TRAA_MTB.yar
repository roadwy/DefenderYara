
rule Backdoor_BAT_Crysan_TRAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.TRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 1d 00 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 20 ?? ?? 00 00 59 d2 9c 00 07 17 58 0b 07 02 7b ?? 00 00 04 8e 69 fe 04 0c 08 2d d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}