
rule Trojan_BAT_AveMaria_NECL_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 04 03 8e 69 14 14 17 28 ?? ?? 00 06 d6 13 07 11 07 04 5f 13 08 03 11 06 03 8e 69 14 14 17 28 ?? ?? 00 06 91 13 09 08 11 06 16 16 02 17 8d 03 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 16 16 11 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}