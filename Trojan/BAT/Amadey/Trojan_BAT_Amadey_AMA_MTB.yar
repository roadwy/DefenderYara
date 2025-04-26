
rule Trojan_BAT_Amadey_AMA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 2b 06 07 28 06 00 00 06 06 6f 22 00 00 0a 25 0b 2d f0 de 0a 06 2c 06 06 6f 23 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Amadey_AMA_MTB_2{
	meta:
		description = "Trojan:BAT/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 2c eb 73 ?? 00 00 0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Amadey_AMA_MTB_3{
	meta:
		description = "Trojan:BAT/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 13 05 08 20 0b 01 00 00 33 0d 11 05 20 98 00 00 00 58 68 13 05 2b 0b 11 05 20 a8 00 00 00 58 68 13 05 06 11 05 6a 16 6f ?? 00 00 0a 26 11 04 06 6f ?? 00 00 0a 69 6f ?? 00 00 0a 11 04 02 7b 1a 00 00 04 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}