
rule Trojan_BAT_ClipBanker_ND_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 11 04 07 09 06 25 17 58 0a 6f 03 00 00 0a 61 d2 6f 04 00 00 0a 06 09 6f 05 00 00 0a 5d 0a 11 05 17 58 } //2
		$a_81_1 = {65 34 62 30 30 62 61 33 2d 36 35 64 62 2d 34 30 30 30 2d 61 63 31 31 2d 65 33 39 31 66 33 32 32 31 61 35 63 } //1 e4b00ba3-65db-4000-ac11-e391f3221a5c
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}