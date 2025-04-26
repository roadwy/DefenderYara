
rule Trojan_Win64_BumbleBee_MKB_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b 84 24 64 02 00 00 44 8b 8c 24 9c 02 00 00 44 8b 94 24 a0 02 00 00 44 8b 9c 24 a4 02 00 00 48 8b 8c 24 48 02 00 00 48 8d 94 24 98 02 00 00 44 89 84 24 20 02 00 00 45 89 d8 44 89 8c 24 1c 02 00 00 45 89 d1 44 8b 94 24 1c 02 00 00 44 89 54 24 20 44 8b 94 24 20 02 00 00 44 89 54 24 28 c7 44 24 30 0c 00 00 00 c7 44 24 38 2a c6 87 47 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}