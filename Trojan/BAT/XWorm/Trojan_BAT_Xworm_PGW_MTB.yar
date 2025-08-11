
rule Trojan_BAT_Xworm_PGW_MTB{
	meta:
		description = "Trojan:BAT/Xworm.PGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 16 fe 01 13 05 11 05 2c 0f 02 11 04 02 11 04 91 20 ?? 00 00 00 61 b4 9c 11 04 17 d6 13 04 11 04 09 31 d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Xworm_PGW_MTB_2{
	meta:
		description = "Trojan:BAT/Xworm.PGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 fe 06 38 00 00 06 73 ?? 00 00 0a 0a 06 14 73 ?? 00 00 0a 20 10 27 00 00 20 98 3a 00 00 6f ?? 00 00 0a 73 ?? 00 00 0a 20 10 27 00 00 20 98 3a 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Xworm_PGW_MTB_3{
	meta:
		description = "Trojan:BAT/Xworm.PGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 1f 16 94 13 23 11 1f 17 94 13 24 02 11 23 11 24 6f ?? 00 00 0a 13 25 0e 0b 2c 39 11 1b 18 31 34 } //5
		$a_01_1 = {11 27 06 61 06 61 d2 13 27 11 28 16 61 d2 13 28 11 29 06 61 06 61 d2 13 29 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}