
rule Trojan_BAT_Perseus_AP_MTB{
	meta:
		description = "Trojan:BAT/Perseus.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c 16 0d 2b 22 08 09 9a 13 04 11 04 6f 94 00 00 0a 2c 10 11 04 6f 95 00 00 0a 6f 2c 00 00 0a 10 01 2b 0a 09 17 58 0d 09 08 8e 69 32 d8 } //00 00 
	condition:
		any of ($a_*)
 
}