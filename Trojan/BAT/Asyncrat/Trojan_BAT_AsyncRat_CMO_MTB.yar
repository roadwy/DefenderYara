
rule Trojan_BAT_AsyncRat_CMO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 83 00 00 0a 7e 2e 00 00 04 08 07 6f 84 00 00 0a 28 44 00 00 0a 13 04 28 83 00 00 0a 11 04 16 11 04 8e 69 6f 84 00 00 0a 28 85 00 00 0a 13 05 7e 30 00 00 04 } //5
		$a_01_1 = {09 07 6f 4a 00 00 0a 17 73 4b 00 00 0a 13 04 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}