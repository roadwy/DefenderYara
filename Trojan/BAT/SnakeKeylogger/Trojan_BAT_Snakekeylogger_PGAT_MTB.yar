
rule Trojan_BAT_Snakekeylogger_PGAT_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.PGAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? ?? 00 0a 0a 12 01 fe 15 30 00 00 02 12 01 12 00 28 ?? ?? 00 0a 7d d3 00 00 04 12 01 12 00 28 ?? ?? 00 0a 7d d4 00 00 04 12 01 12 00 28 ?? ?? 00 0a 7d d5 00 00 04 0e 05 0d 09 39 9b 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}