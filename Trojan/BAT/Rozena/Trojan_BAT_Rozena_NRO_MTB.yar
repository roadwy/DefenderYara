
rule Trojan_BAT_Rozena_NRO_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 72 86 12 00 70 28 90 01 01 00 00 06 0d 73 90 01 01 00 00 0a 13 04 06 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 13 05 11 05 11 04 08 09 6f 90 01 01 00 00 0a 16 73 90 01 01 00 00 0a 13 06 11 06 73 90 01 01 00 00 0a 13 07 11 07 90 00 } //5
		$a_01_1 = {43 61 6c 69 73 74 69 72 6d 61 46 6f 6e 6b 73 69 79 6f 6e 75 } //1 CalistirmaFonksiyonu
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Rozena_NRO_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.NRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 d3 00 00 70 0b 73 90 01 03 0a 13 08 11 08 07 6f 90 01 03 0a 0a de 0c 11 08 2c 07 11 08 6f 90 01 03 0a dc 06 28 90 01 03 0a 02 8e 69 8d 1c 00 00 01 0c 16 13 09 2b 17 08 11 09 02 11 09 91 18 59 20 90 01 03 00 5f d2 9c 11 09 17 58 13 09 11 09 02 8e 69 32 e2 08 8e 69 26 28 90 01 03 06 7e 90 01 03 0a 28 90 01 03 06 0d 7e 90 01 03 0a 20 90 01 03 00 20 90 01 03 00 1a 16 28 90 01 03 06 13 04 06 8e 69 28 90 01 03 0a 13 05 06 16 11 05 06 8e 69 28 90 01 03 0a 11 04 11 05 06 8e 69 28 90 01 03 06 90 00 } //5
		$a_01_1 = {4d 61 69 6c 53 6c 6f 74 57 69 74 68 54 65 73 74 } //1 MailSlotWithTest
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}