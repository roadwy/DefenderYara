
rule Trojan_BAT_AsyncRat_CCJN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 72 f4 6e 00 70 13 04 09 11 04 ?? fa 6e 00 70 28 ?? 00 00 0a 20 00 01 00 00 14 14 17 8d 13 00 00 01 25 16 08 a2 ?? 6b 00 00 0a 75 21 00 00 01 13 05 11 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_CCJN_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 02 09 91 6f ?? ?? ?? ?? 09 04 17 58 58 0d 09 02 8e 69 32 eb 06 6f ?? ?? ?? ?? 0b 07 8e 69 8d ?? ?? ?? ?? 0c 16 13 04 2b 18 08 11 04 07 11 04 91 03 11 04 03 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}