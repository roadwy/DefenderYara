
rule Trojan_BAT_AsyncRat_NEK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 16 02 07 8f ?? 00 00 01 25 47 06 07 1f 10 5d 91 61 d2 52 07 17 58 0b 07 02 8e 69 32 e4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}