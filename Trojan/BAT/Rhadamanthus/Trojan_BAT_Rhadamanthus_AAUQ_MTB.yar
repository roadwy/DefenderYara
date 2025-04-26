
rule Trojan_BAT_Rhadamanthus_AAUQ_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthus.AAUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 16 28 ?? 13 00 06 13 07 20 09 00 00 00 38 ?? ff ff ff 16 13 03 20 05 00 00 00 38 ?? ff ff ff 12 07 28 ?? 06 00 0a 13 05 20 02 00 00 00 38 ?? ff ff ff 73 ?? 05 00 0a 13 02 20 03 00 00 00 38 ?? ff ff ff 11 03 17 58 13 03 20 07 00 00 00 38 ?? ff ff ff 11 03 11 01 28 ?? 13 00 06 3f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}