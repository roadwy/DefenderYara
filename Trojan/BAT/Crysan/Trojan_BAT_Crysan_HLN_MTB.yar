
rule Trojan_BAT_Crysan_HLN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.HLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 02 8e 69 8d 0c 00 00 01 0b 16 0c 2b 13 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}