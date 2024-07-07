
rule Trojan_BAT_AsyncRat_CBYZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CBYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0c 00 00 0a 0a 73 0d 00 00 0a 0b 07 28 90 01 04 03 6f 0f 00 00 0a 6f 10 00 00 0a 0c 06 08 6f 90 01 04 06 18 6f 12 00 00 0a 06 6f 13 00 00 0a 02 16 02 8e 69 6f 14 00 00 0a 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}