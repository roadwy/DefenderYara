
rule Trojan_BAT_AsyncRat_NEF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 06 02 09 6f 19 00 00 0a 11 06 58 11 04 59 1f 1a 28 04 00 00 06 11 04 58 d1 13 07 06 12 07 28 20 00 00 0a 28 21 00 00 0a 0a 2b 1b } //5
		$a_01_1 = {61 00 76 00 79 00 68 00 6b 00 } //5 avyhk
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}