
rule Trojan_BAT_Crysan_AYA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 21 2b 37 00 11 0a 11 21 11 20 6f ?? 00 00 0a 13 22 11 0c 12 22 28 ?? 00 00 0a 1f 10 62 12 22 28 ?? 00 00 0a 1e 62 60 12 22 28 ?? 00 00 0a 60 6a 61 13 0c 00 11 21 19 58 13 21 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}