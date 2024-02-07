
rule Trojan_BAT_Bladabindi_DJ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {a2 25 17 06 11 90 01 01 17 28 90 01 03 0a a2 25 18 07 11 90 01 01 17 28 90 01 03 0a a2 25 19 08 11 90 01 01 17 28 90 01 03 0a a2 25 1a 09 11 90 01 01 17 28 90 01 03 0a a2 25 1b 11 04 11 90 01 01 17 28 90 01 03 0a 90 09 0b 00 1f 90 01 01 8d 90 01 03 01 25 16 11 90 00 } //01 00 
		$a_81_1 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}