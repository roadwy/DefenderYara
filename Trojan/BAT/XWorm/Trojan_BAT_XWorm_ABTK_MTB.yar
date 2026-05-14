
rule Trojan_BAT_XWorm_ABTK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ABTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 16 16 6f ?? 00 00 0a 13 06 11 04 17 16 6f ?? 00 00 0a 13 07 11 05 16 12 06 28 ?? 00 00 0a 9c 11 05 17 12 06 28 ?? 00 00 0a 9c 11 05 18 12 06 28 ?? 00 00 0a 9c 11 05 19 12 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_XWorm_ABTK_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.ABTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 17 58 20 00 01 00 00 5d 13 08 11 09 09 11 08 94 58 20 00 01 00 00 5d 13 09 09 11 08 94 13 0b 09 11 08 09 11 09 94 9e 09 11 09 11 0b 9e 09 09 11 08 94 09 11 09 94 58 20 00 01 00 00 5d 94 13 0c 06 11 0a 06 8e 69 5d 91 07 11 0a 07 8e 69 5d 91 61 d2 13 0d 08 11 0a 02 11 0a 91 11 0c d2 61 11 0d 61 d2 9c 11 0a 17 58 13 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}