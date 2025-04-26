
rule Trojan_BAT_Rozena_SPQA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 28 01 00 00 fe 0c 29 01 00 00 9a fe 0e 2a 01 00 00 00 7e ?? ?? ?? 04 11 c3 fe 0c 2a 01 00 00 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 c3 17 58 13 c3 00 fe 0c 29 01 00 00 17 58 fe 0e 29 01 00 00 fe 0c 29 01 00 00 fe 0c 28 01 00 00 8e 69 32 a3 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}