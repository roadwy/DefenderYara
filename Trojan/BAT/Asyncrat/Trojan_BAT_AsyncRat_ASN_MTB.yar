
rule Trojan_BAT_AsyncRat_ASN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 19 00 06 08 8f 0f 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 00 08 17 58 0c 08 06 8e 69 fe 04 0d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}