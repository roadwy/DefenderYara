
rule Trojan_BAT_Marsilia_AMS_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 00 1f 0d 02 07 6f 11 00 00 0a 28 05 00 00 06 16 28 02 00 00 06 0c de 16 07 2c 07 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Marsilia_AMS_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 4c 06 6f ?? 00 00 0a 74 16 00 00 01 0b 18 8d 18 00 00 01 25 16 7e 26 00 00 0a a2 25 17 7e 26 00 00 0a a2 0c 07 72 99 00 00 70 08 0d 09 6f ?? 00 00 0a 28 ?? 00 00 0a 2d 14 08 17 9a 72 ab 00 00 70 08 16 9a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}