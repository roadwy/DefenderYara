
rule Trojan_BAT_Vipkeylogger_CE_MTB{
	meta:
		description = "Trojan:BAT/Vipkeylogger.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 12 02 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 fe 04 16 fe 01 } //4
		$a_03_1 = {1b 13 04 38 ?? 01 00 00 03 6f ?? 00 00 0a 04 fe 04 16 fe 01 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}