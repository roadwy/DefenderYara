
rule Trojan_BAT_AsyncRat_RPY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1f 16 5d 91 13 04 07 09 91 11 04 61 13 05 09 17 58 08 5d 13 06 07 11 06 91 13 07 20 00 01 00 00 13 08 11 05 11 07 59 11 08 58 11 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 28 1a 01 00 06 00 02 07 6c 02 28 0d 01 00 06 6c 5b 23 00 00 00 00 00 00 59 40 5a 28 10 01 00 06 00 07 17 d6 0b 07 06 31 d5 02 17 73 2e 01 00 06 6f 28 01 00 06 00 2a 00 00 00 13 30 01 00 07 00 00 00 07 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}