
rule Trojan_BAT_Lazy_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 59 18 5a 6a 59 07 6a 58 13 0b 11 0b d1 13 0c 11 07 08 17 58 11 0c 6f ?? 00 00 0a 00 08 18 58 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}