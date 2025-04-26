
rule Trojan_BAT_AsyncRat_AZAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 1c 13 0b 2b a8 09 74 ?? 00 00 01 09 75 ?? 00 00 01 6f ?? 00 00 0a 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 19 13 0b 2b 80 } //2
		$a_03_1 = {02 16 02 8e 69 6f ?? 00 00 0a 11 07 75 ?? 00 00 01 6f ?? 00 00 0a 16 13 0f 2b bf } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}