
rule Trojan_BAT_Snakekeylogger_OOYF_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.OOYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 6f 90 01 03 0a 09 18 6f 90 01 03 0a 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {4b 69 6e 6f 6d 61 6e 69 61 6b 20 4c 69 62 72 61 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}