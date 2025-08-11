
rule Trojan_BAT_Crysan_EARX_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EARX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 0b 00 00 01 0a 16 0b 38 25 00 00 00 02 07 91 0c 08 18 28 06 00 00 06 0c 08 03 59 07 59 20 ff 00 00 00 5f d2 0c 08 66 d2 0c 06 07 08 9c 07 17 58 0b 07 02 8e 69 32 d5 06 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}