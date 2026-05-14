
rule Trojan_BAT_AsyncRat_ASA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 13 02 11 12 11 13 16 11 13 8e 69 28 ?? 00 00 0a 7e 07 00 00 04 12 03 7b 0b 00 00 04 11 0c 11 10 58 11 13 11 13 8e 69 12 01 6f ?? 00 00 06 2d 06 73 0b 00 00 0a 7a 11 0d 1f 28 58 13 0d 11 0f 17 58 13 0f 11 0f 11 0e 32 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASA_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 07 06 28 ?? 00 00 0a 26 03 17 18 16 73 ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a de 0a 07 2c 06 07 6f ?? 00 00 0a dc 03 03 28 } //2
		$a_01_1 = {0b 16 0c 2b 13 07 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}