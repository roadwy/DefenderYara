
rule Trojan_BAT_Lazy_SPDD_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 08 09 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 16 31 01 2a 11 04 17 58 13 04 11 04 1b 32 e5 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}