
rule Trojan_BAT_XWorm_ARM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 3a 06 08 9a 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0d 09 59 08 1f ?? 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_XWorm_ARM_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 1a 5a 11 08 1b 5a 58 1f 0a 5d 17 58 13 09 11 08 1f 0a 5d 17 58 13 0a 09 1f 0a 5d 17 58 13 0b 02 09 11 08 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0c 11 0d 03 } //2
		$a_01_1 = {43 00 68 00 69 00 6e 00 68 00 44 00 6f 00 2e 00 54 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 73 00 } //1 ChinhDo.Transactions
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}