
rule Trojan_BAT_Snakekeylogger_AGEF_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.AGEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe 06 2b 00 00 06 73 34 00 00 0a 6f 90 01 03 0a 00 73 09 00 00 06 0b 14 0c 08 14 fe 03 0d 09 2c 16 00 06 08 90 00 } //01 00 
		$a_01_1 = {48 00 65 00 6c 00 70 00 65 00 72 00 5f 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 } //00 00  Helper_Classes
	condition:
		any of ($a_*)
 
}