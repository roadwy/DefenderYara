
rule Trojan_BAT_Snakekeylogger_IEGA_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.IEGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 13 04 00 70 6f 90 01 03 0a 1e 8d 63 00 00 01 17 73 78 00 00 0a 0b 73 79 00 00 0a 0c 08 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 08 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 08 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 0d 09 8e 69 1f 10 59 90 00 } //01 00 
		$a_01_1 = {35 00 38 00 35 00 47 00 35 00 34 00 53 00 34 00 43 00 35 00 48 00 42 00 43 00 35 00 53 00 59 00 44 00 35 00 34 00 35 00 34 00 32 00 } //01 00  585G54S4C5HBC5SYD54542
		$a_01_2 = {53 00 6e 00 61 00 6b 00 65 00 49 00 } //00 00  SnakeI
	condition:
		any of ($a_*)
 
}