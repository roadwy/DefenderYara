
rule Trojan_BAT_Crysan_AAFB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 8e 69 8d ?? 00 00 01 0d 16 13 05 2b 18 09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 e1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}