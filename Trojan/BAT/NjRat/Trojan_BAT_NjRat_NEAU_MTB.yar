
rule Trojan_BAT_NjRat_NEAU_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 38 21 00 00 00 7e 2f 00 00 04 07 9a 06 28 b2 00 00 0a 39 0b 00 00 00 7e 30 00 00 04 74 2e 00 00 01 2a 07 17 58 0b 07 } //10
		$a_01_1 = {4d 57 67 61 77 44 63 57 63 61 67 54 76 56 6d 73 67 37 48 } //5 MWgawDcWcagTvVmsg7H
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}