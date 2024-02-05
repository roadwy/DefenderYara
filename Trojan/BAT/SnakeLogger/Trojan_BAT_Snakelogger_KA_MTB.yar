
rule Trojan_BAT_Snakelogger_KA_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {77 69 74 68 6f 75 74 73 74 61 72 74 75 70 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}