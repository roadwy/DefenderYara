
rule Trojan_BAT_ClipBanker_AO_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 2c 26 16 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 1f 19 31 15 08 6f ?? 00 00 0a 1f 24 2f 0b 7e ?? 00 00 0a 06 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}