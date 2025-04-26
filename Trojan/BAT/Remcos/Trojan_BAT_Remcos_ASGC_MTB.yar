
rule Trojan_BAT_Remcos_ASGC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 00 8e 69 28 ?? 00 00 0a 20 01 00 00 00 7e ?? 1e 00 04 7b ?? 1e 00 04 3a ?? ff ff ff 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Remcos_ASGC_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ASGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0c 08 11 0a 91 61 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11 } //1
		$a_01_1 = {07 11 09 91 13 0c 20 00 01 00 00 13 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}