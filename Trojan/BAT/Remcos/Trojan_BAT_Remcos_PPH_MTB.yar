
rule Trojan_BAT_Remcos_PPH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 42 07 11 05 11 06 6f ?? 00 00 0a 13 07 08 6f ?? 00 00 0a 19 58 09 30 0a 08 11 07 28 ?? 00 00 06 2b 1b 09 08 6f ?? 00 00 0a 59 13 08 11 08 16 31 1c 08 11 07 11 08 28 ?? 00 00 06 2b 10 11 06 17 58 13 06 11 06 07 6f ?? 00 00 0a 32 b4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}