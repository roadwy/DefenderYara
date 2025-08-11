
rule Trojan_BAT_Androm_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Androm.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 07 11 07 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Androm_AMAB_MTB_2{
	meta:
		description = "Trojan:BAT/Androm.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 00 6f ?? 00 00 0a 11 00 28 ?? 00 00 06 28 ?? 00 00 06 13 08 20 02 00 00 00 7e ?? 08 00 04 7b ?? 08 00 04 39 } //5
		$a_03_1 = {11 07 11 08 16 73 ?? 00 00 0a 13 0c 20 00 00 00 00 7e ?? 08 00 04 7b ?? 08 00 04 3a ?? 00 00 00 26 20 00 00 00 00 38 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}