
rule Trojan_BAT_LokiBot_CXRE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1c 08 07 06 6f ?? ?? ?? ?? 13 09 11 04 12 09 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 06 17 58 0a 06 08 6f ?? ?? ?? ?? fe 04 13 06 11 06 2d d5 07 17 58 0b 07 08 6f ?? ?? ?? ?? fe 04 13 07 11 07 2d be } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}