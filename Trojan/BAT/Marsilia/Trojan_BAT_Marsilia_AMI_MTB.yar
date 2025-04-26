
rule Trojan_BAT_Marsilia_AMI_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 00 06 0b 16 0c 2b 27 07 08 9a 0d 00 09 6f 36 00 00 0a 72 01 00 00 70 1b 6f 37 00 00 0a 13 04 11 04 2c 06 00 17 13 05 2b 10 00 08 17 58 0c 08 07 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Marsilia_AMI_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 9a 16 9a 7e ?? 00 00 04 20 ?? bd 66 06 28 ?? 00 00 06 28 ?? 00 00 0a 2d 11 06 08 9a 16 9a 28 ?? 00 00 06 28 ?? 00 00 0a 2b 05 28 ?? 00 00 0a 06 08 9a 17 9a 28 ?? 00 00 06 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}