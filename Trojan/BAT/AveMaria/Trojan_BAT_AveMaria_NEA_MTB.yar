
rule Trojan_BAT_AveMaria_NEA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 0d 00 00 04 11 04 7e ?? ?? ?? 04 11 04 91 20 ?? ?? ?? 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04 } //5
		$a_01_1 = {49 51 6e 75 69 6e } //1 IQnuin
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AveMaria_NEA_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 09 8f 65 00 00 01 72 94 0a 00 70 28 6b 00 00 0a 6f 6c 00 00 0a 26 00 09 17 58 0d 09 07 8e 69 fe 04 13 04 11 04 2d d6 } //1
		$a_01_1 = {35 00 58 00 54 00 4f 00 44 00 35 00 47 00 34 00 51 00 35 00 34 00 47 00 5a 00 38 00 35 00 37 00 42 00 53 00 43 00 38 00 37 00 34 00 } //1 5XTOD5G4Q54GZ857BSC874
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AveMaria_NEA_MTB_3{
	meta:
		description = "Trojan:BAT/AveMaria.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 ca 01 00 06 00 11 08 20 ?? ?? ?? 75 5a 20 ?? ?? ?? 73 61 38 ?? ?? ?? ff 00 11 08 20 ?? ?? ?? b3 5a 20 ?? ?? ?? 6a 61 38 ?? ?? ?? ff 02 28 ?? ?? ?? 06 09 28 ?? ?? ?? 06 00 11 08 20 ?? ?? ?? 59 5a 20 ?? ?? ?? 87 61 38 ?? ?? ?? ff 11 05 28 ?? ?? ?? 06 20 ?? ?? ?? 8a 28 ?? ?? ?? 2b } //5
		$a_01_1 = {4d 61 54 61 63 47 69 61 } //1 MaTacGia
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}