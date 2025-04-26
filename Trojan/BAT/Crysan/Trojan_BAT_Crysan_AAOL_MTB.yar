
rule Trojan_BAT_Crysan_AAOL_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 22 11 07 11 09 58 06 11 09 58 47 08 11 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 52 11 09 17 58 13 09 11 09 07 8e 69 32 d7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}