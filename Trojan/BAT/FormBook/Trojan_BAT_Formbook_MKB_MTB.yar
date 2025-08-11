
rule Trojan_BAT_Formbook_MKB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 0b 6f a8 01 00 0a 58 13 0c 11 24 17 d6 13 24 11 24 20 40 42 0f 00 31 e5 11 05 19 11 05 18 9a 74 75 00 00 1b 11 06 28 ?? 02 00 0a 28 ?? 01 00 06 14 72 52 17 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 23 00 00 00 00 00 00 00 00 13 0d 17 13 25 11 0d 11 25 6c 23 00 00 00 00 00 00 00 40 28 ?? 00 00 0a 58 13 0d 11 25 17 d6 13 25 11 25 20 a0 86 01 00 31 db } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}