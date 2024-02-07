
rule Trojan_BAT_SnakeKeylogger_PSP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 11 0c 09 59 28 90 01 03 0a 13 0d 11 0c 09 58 17 58 04 6f 90 01 03 0a 28 90 01 03 0a 13 0e 11 0d 13 0f 2b 42 00 07 11 0f 91 13 10 11 10 2c 02 90 00 } //01 00 
		$a_01_1 = {5a 69 6e 64 67 65 53 61 78 74 65 } //01 00  ZindgeSaxte
		$a_01_2 = {45 7a 6c 65 6e 6b 6f 6b 61 } //00 00  Ezlenkoka
	condition:
		any of ($a_*)
 
}