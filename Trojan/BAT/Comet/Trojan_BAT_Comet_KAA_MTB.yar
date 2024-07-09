
rule Trojan_BAT_Comet_KAA_MTB{
	meta:
		description = "Trojan:BAT/Comet.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 07 02 11 07 91 09 61 07 11 04 91 61 9c 07 28 ?? 00 00 0a 11 04 07 8e b7 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 07 17 d6 13 07 11 07 11 08 31 cb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}