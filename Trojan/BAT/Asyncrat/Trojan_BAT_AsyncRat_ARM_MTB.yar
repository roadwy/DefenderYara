
rule Trojan_BAT_AsyncRat_ARM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fe 04 13 0a 11 0a 2c 13 06 7b ?? 00 00 04 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 06 17 58 13 06 11 06 02 6f ?? 00 00 0a 2f 10 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 2b 01 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}