
rule Trojan_BAT_LokiBot_CXRF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 22 00 07 11 04 11 05 6f ?? ?? ?? ?? 13 06 08 12 06 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 00 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? ?? fe 04 13 07 11 07 2d ce 00 11 04 17 58 13 04 11 04 07 6f ?? ?? ?? ?? fe 04 13 08 11 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}