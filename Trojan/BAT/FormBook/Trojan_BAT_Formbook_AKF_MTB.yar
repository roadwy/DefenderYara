
rule Trojan_BAT_Formbook_AKF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 16 07 11 04 06 11 04 19 5a 58 1f 18 5d 1f 0c 59 9e 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dd } //1
		$a_01_1 = {0a 16 13 07 2b 1c 00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_BAT_Formbook_AKF_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6c 07 16 9a 16 99 5a a1 25 17 12 09 28 ?? 00 00 0a 6c 07 17 9a 17 99 5a a1 25 18 12 09 28 ?? 00 00 0a 6c 07 18 9a 18 99 5a a1 13 0a 19 8d ?? 00 00 01 25 16 11 0a 16 99 d2 9c 25 17 11 0a 17 99 } //2
		$a_01_1 = {48 61 72 76 65 73 74 50 69 67 6d 65 6e 74 53 65 71 75 65 6e 63 65 } //1 HarvestPigmentSequence
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Formbook_AKF_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 27 00 07 11 05 11 06 6f ?? ?? ?? 0a 13 07 08 12 07 28 ?? ?? ?? 0a 8c 5a 00 00 01 6f ?? ?? ?? 0a 26 00 11 06 17 58 13 06 11 06 07 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d c9 00 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d ac } //2
		$a_01_1 = {53 00 61 00 6c 00 65 00 73 00 49 00 6e 00 76 00 65 00 6e 00 74 00 6f 00 72 00 79 00 } //1 SalesInventory
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}