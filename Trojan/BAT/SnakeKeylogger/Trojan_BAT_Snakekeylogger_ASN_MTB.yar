
rule Trojan_BAT_Snakekeylogger_ASN_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 4d 02 00 70 28 80 00 00 06 15 2d 22 26 28 98 00 00 0a 06 6f 99 00 00 0a 28 9a 00 00 0a 1c 2d 11 26 02 07 28 7f 00 00 06 18 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c3 } //01 00 
		$a_01_1 = {16 1d 2d 0c 26 03 8e 69 17 59 1b 2d 06 26 2b 24 0a 2b f2 0b 2b f8 03 06 91 1e 2d 15 26 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //00 00 
	condition:
		any of ($a_*)
 
}