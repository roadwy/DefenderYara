
rule Trojan_BAT_Snakekeylogger_INFA_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.INFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 6f 90 01 03 0a 09 08 6f 90 01 03 0a 09 18 6f 90 01 03 0a 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 28 90 01 03 06 74 31 00 00 01 6f 90 01 03 0a 17 9a 80 5b 00 00 04 23 66 66 66 66 66 66 28 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}