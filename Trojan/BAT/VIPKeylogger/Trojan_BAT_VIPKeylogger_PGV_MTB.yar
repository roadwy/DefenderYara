
rule Trojan_BAT_VIPKeylogger_PGV_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.PGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 13 12 12 06 28 ?? 00 00 0a 0e 04 7b 20 00 00 04 06 0e 04 7b 20 00 00 04 8e 69 5d 91 61 d2 13 13 12 06 28 ?? 00 00 0a 0e 04 7b 20 00 00 04 11 05 0e 04 7b 20 00 00 04 8e 69 5d 91 61 d2 13 14 12 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}