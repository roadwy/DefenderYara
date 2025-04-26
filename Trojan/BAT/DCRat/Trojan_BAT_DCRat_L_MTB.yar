
rule Trojan_BAT_DCRat_L_MTB{
	meta:
		description = "Trojan:BAT/DCRat.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 03 06 1e 58 4b 61 54 06 4b 06 1a 58 4b 61 06 1e 58 4b 61 1e 06 4b 06 } //2 ͘Ḇ䭘呡䬆ᨆ䭘١堞態؞ً
	condition:
		((#a_01_0  & 1)*2) >=2
 
}