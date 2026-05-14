
rule Trojan_BAT_AsyncRat_AWQB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AWQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 58 20 00 01 00 00 5d 13 06 11 07 07 11 06 91 58 20 00 01 00 00 5d 13 07 07 11 06 91 13 09 07 11 06 07 11 07 91 9c 07 11 07 11 09 9c 07 07 11 06 91 07 11 07 91 58 20 00 01 00 00 5d 91 13 0a 06 11 08 02 11 08 91 11 0a 61 d2 9c 11 08 17 58 13 08 11 08 02 8e 69 32 a5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}