
rule Trojan_BAT_AsyncRat_NEAQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 16 9a 0a 02 17 9a 74 ?? 00 00 01 0b 02 18 9a a5 ?? 00 00 01 0c 02 19 9a 74 ?? 00 00 1b 0d 06 07 08 09 28 ?? 00 00 0a 13 04 2b 00 11 04 2a } //10
		$a_01_1 = {32 00 30 00 32 00 30 00 61 00 32 00 30 00 32 00 30 00 6d 00 32 00 30 00 32 00 30 00 73 00 32 00 30 00 32 00 30 00 69 00 32 00 30 00 32 00 30 00 2e 00 32 00 30 00 32 00 30 00 64 00 32 00 30 00 32 00 30 00 6c 00 32 00 30 00 32 00 30 00 6c 00 32 00 30 00 32 00 30 00 } //5 2020a2020m2020s2020i2020.2020d2020l2020l2020
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}