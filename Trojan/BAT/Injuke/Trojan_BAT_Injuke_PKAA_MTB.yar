
rule Trojan_BAT_Injuke_PKAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0b 07 72 b9 00 00 70 18 18 8d ?? 00 00 01 25 16 7e ?? 00 00 04 a2 25 17 7e 14 00 00 04 a2 28 ?? 00 00 0a 74 ?? 00 00 01 0d 00 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 de 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}