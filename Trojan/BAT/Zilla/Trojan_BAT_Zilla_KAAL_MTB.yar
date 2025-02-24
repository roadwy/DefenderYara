
rule Trojan_BAT_Zilla_KAAL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 11 11 08 59 06 5d 13 12 11 05 11 12 7e ?? 00 00 04 11 11 91 11 06 11 11 11 07 5d 91 61 d2 9c 00 11 11 17 58 13 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}