
rule Trojan_BAT_Remcos_FAT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 11 04 6f 90 01 01 00 00 0a 11 05 18 6f 90 01 01 00 00 0a 11 05 18 6f 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a 13 06 11 06 07 16 07 8e 69 6f 90 01 01 00 00 0a 13 07 28 90 01 01 00 00 0a 11 07 6f 90 01 01 00 00 0a 13 08 11 08 6f 90 01 01 00 00 0a 13 0a de 52 02 38 90 01 01 ff ff ff 6f 90 01 01 00 00 0a 38 90 01 01 ff ff ff 0a 38 90 01 01 ff ff ff 06 38 90 01 01 ff ff ff 28 90 01 01 00 00 0a 38 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}