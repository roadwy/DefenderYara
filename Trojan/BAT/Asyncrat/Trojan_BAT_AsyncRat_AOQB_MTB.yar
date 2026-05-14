
rule Trojan_BAT_AsyncRat_AOQB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AOQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 0b 9a 13 0c 11 0c 28 ?? ?? 00 0a 13 0e 11 0e 2c 02 2b 40 00 11 0c 12 0d 28 ?? ?? 00 0a 13 0f 11 0f 2c 2f 11 0d 11 07 da 13 10 11 10 16 32 0e 11 10 20 ff 00 00 00 fe 02 16 fe 01 2b 01 16 13 11 11 11 2c 0c 11 04 11 10 b4 6f ?? ?? 00 0a 00 00 00 00 00 11 0b 17 d6 13 0b 11 0b 11 0a 31 9f 11 04 6f ?? ?? 00 0a 13 08 11 04 6f ?? ?? 00 0a 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}