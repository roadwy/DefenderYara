
rule Trojan_BAT_ClipBanker_CI_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 6f ?? 00 00 0a 25 6f ?? 00 00 0a 6f ?? 00 00 0a 7b ?? 00 00 04 74 ?? 00 00 01 74 ?? 00 00 01 25 0a 28 ?? 00 00 0a 16 fe } //2
		$a_03_1 = {01 13 04 1f ?? 58 1e 5c 18 5a 17 59 e0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}