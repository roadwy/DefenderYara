
rule Trojan_BAT_LummaC_LAT_MTB{
	meta:
		description = "Trojan:BAT/LummaC.LAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 14 72 91 48 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 20 b6 fe 0d 00 8c 88 00 00 01 28 ?? 01 00 0a 17 8c 88 00 00 01 28 ?? 01 00 0a 28 ?? 00 00 0a 80 0b 00 00 04 03 74 8a 00 00 1b 20 b6 fe 0d 00 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 07 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}