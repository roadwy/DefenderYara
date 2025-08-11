
rule Trojan_BAT_AsyncRat_AHQA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AHQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0e 04 00 fe 0c 04 00 20 01 00 00 00 40 00 00 00 00 02 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0b 06 8e 69 8d 1f 00 00 01 0c 16 0d 38 13 00 00 00 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 3f e4 ff ff ff } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}