
rule Trojan_BAT_XWorm_AB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 80 06 00 00 04 2b 11 7e 07 00 00 04 7e 06 00 00 04 16 91 6f 5f 00 00 0a 38 ab 00 00 00 7e 07 00 00 04 7e 06 00 00 04 16 06 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_XWorm_AB_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 06 03 09 6f ?? 00 00 0a 59 13 07 09 17 8d 80 00 00 01 25 16 12 06 28 77 00 00 0a 9c 6f ?? 00 00 0a 00 11 07 17 59 25 13 07 16 fe 02 16 fe 01 13 10 11 10 2c 05 38 ee 00 00 00 09 17 8d 80 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_XWorm_AB_MTB_3{
	meta:
		description = "Trojan:BAT/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 0a 03 07 6f ?? 00 00 0a 59 13 0b 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 13 16 11 16 2c 05 38 ?? 00 00 00 08 6f ?? 00 00 0a 20 ff ff ff 7f 6a 5f 69 13 0c 11 0c 06 7b 8f 01 00 04 61 11 05 58 11 06 58 13 0d 11 0d 8c ?? 00 00 01 28 ?? 00 00 0a 00 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 13 17 11 17 2c 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}