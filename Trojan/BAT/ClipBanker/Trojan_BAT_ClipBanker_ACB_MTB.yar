
rule Trojan_BAT_ClipBanker_ACB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 17 7e 01 00 00 04 07 7e 01 00 00 04 07 9a 28 ?? 00 00 06 a2 07 17 58 0b 07 7e 01 00 00 04 8e 69 } //2
		$a_03_1 = {d2 1f 18 26 26 06 13 04 16 13 05 11 04 12 05 28 ?? 00 00 0a 07 09 02 09 6f ?? 00 00 0a d2 17 61 d1 9d de 0c } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}