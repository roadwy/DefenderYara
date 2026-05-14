
rule Trojan_BAT_AsyncRat_AITB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AITB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 7e 00 02 07 6f ?? 00 00 0a 0c 08 1f 61 32 07 08 1f 7a fe 02 2b 01 17 00 13 05 11 05 2d 21 00 08 1f 0d 58 0d 09 1f 7a fe 02 16 fe 01 13 05 11 05 2d 05 09 1f 1a 59 0d 06 07 09 d1 9d 00 2b 3b 08 1f 41 32 07 08 1f 5a fe 02 2b 01 17 00 13 05 11 05 2d 21 00 08 1f 0d 58 0d 09 1f 5a fe 02 16 fe 01 13 05 11 05 2d 05 09 1f 1a 59 0d 06 07 09 d1 9d 00 2b 06 00 06 07 08 9d 00 00 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 13 05 11 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}