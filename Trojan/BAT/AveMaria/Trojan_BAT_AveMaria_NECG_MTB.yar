
rule Trojan_BAT_AveMaria_NECG_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 74 14 00 00 01 72 ?? 00 00 70 20 00 01 00 00 14 14 14 6f 22 00 00 0a 74 22 00 00 01 28 23 00 00 0a 2a } //5
		$a_01_1 = {46 69 67 68 74 } //2 Fight
		$a_01_2 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}