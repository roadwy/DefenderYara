
rule Trojan_BAT_AsyncRat_SGC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0d 00 00 06 11 00 6f 03 00 00 0a 28 0e 00 00 06 28 01 00 00 2b 6f 05 00 00 0a 28 02 00 00 2b } //1
		$a_00_1 = {59 6d 63 66 63 62 64 74 73 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Ymcfcbdts.Properties
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}