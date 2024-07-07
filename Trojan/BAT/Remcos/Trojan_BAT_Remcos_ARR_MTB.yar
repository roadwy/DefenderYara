
rule Trojan_BAT_Remcos_ARR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 14 7d 07 00 00 04 02 28 90 01 03 0a 00 00 02 20 f4 01 00 00 28 90 01 03 0a 00 02 20 bc 02 00 00 28 90 01 03 0a 00 02 72 01 00 00 70 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 30 00 11 06 11 04 5d 13 09 11 06 11 04 5b 13 0a 09 11 09 11 0a 6f 90 01 03 0a 13 0b 08 12 0b 28 90 01 03 0a 6f 90 01 03 0a 00 11 06 17 58 13 06 00 11 06 11 04 11 05 5a fe 04 13 0c 11 0c 2d c1 90 00 } //2
		$a_01_1 = {43 00 68 00 61 00 72 00 67 00 69 00 6e 00 67 00 50 00 69 00 6c 00 65 00 } //1 ChargingPile
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Remcos_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 72 97 18 00 70 6f 90 01 03 0a 74 02 00 00 1b 0c 08 28 90 01 03 0a 00 07 08 6f 90 01 03 0a 00 07 06 72 a3 18 00 70 6f 90 01 03 0a 74 02 00 00 1b 6f 90 01 03 0a 00 07 06 72 af 18 00 70 6f 90 01 03 0a 74 02 00 00 1b 6f 90 01 03 0a 00 02 28 90 00 } //2
		$a_01_1 = {53 00 65 00 68 00 69 00 72 00 54 00 61 00 68 00 6d 00 69 00 6e 00 45 00 74 00 6d 00 65 00 4f 00 79 00 75 00 6e 00 75 00 } //1 SehirTahminEtmeOyunu
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}