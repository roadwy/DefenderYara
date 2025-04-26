
rule Trojan_BAT_AsyncRat_ASA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 13 02 11 12 11 13 16 11 13 8e 69 28 ?? 00 00 0a 7e 07 00 00 04 12 03 7b 0b 00 00 04 11 0c 11 10 58 11 13 11 13 8e 69 12 01 6f ?? 00 00 06 2d 06 73 0b 00 00 0a 7a 11 0d 1f 28 58 13 0d 11 0f 17 58 13 0f 11 0f 11 0e 32 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}