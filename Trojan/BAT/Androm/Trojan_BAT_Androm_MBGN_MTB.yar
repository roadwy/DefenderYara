
rule Trojan_BAT_Androm_MBGN_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 3a 16 13 07 2b 2a 09 11 04 11 06 58 11 05 11 07 58 6f 90 01 01 00 00 0a 13 08 12 08 28 90 01 01 00 00 0a 13 09 08 07 11 09 9c 07 17 58 0b 11 07 17 58 13 07 11 07 17 32 d1 90 00 } //1
		$a_01_1 = {5a 00 6c 00 6d 00 32 00 30 00 32 00 33 00 } //1 Zlm2023
		$a_01_2 = {41 00 61 00 64 00 73 00 2e 00 53 00 6f 00 72 00 74 00 73 00 2e 00 48 00 65 00 } //1 Aads.Sorts.He
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}