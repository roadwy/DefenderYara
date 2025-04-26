
rule Trojan_BAT_Heracles_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 d2 13 [0-0a] 20 ff 00 00 00 5f d2 13 [0-14] 61 13 [0-14] 20 ff 00 00 00 5f d2 9c 00 11 ?? 17 6a 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}