
rule Trojan_BAT_Wagex_SPQM_MTB{
	meta:
		description = "Trojan:BAT/Wagex.SPQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 05 00 00 04 02 7b 06 00 00 04 28 ?? ?? ?? 06 13 17 02 72 3c 03 00 70 12 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 02 7b 06 00 00 04 72 48 03 00 70 02 7b 04 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 72 e7 00 00 70 28 ?? ?? ?? 06 00 00 11 16 17 58 13 16 11 16 02 7b 04 00 00 04 28 ?? ?? ?? 0a fe 04 13 18 11 18 2d 97 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}