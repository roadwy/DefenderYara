
rule Trojan_BAT_LokiBot_EQ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 17 a2 09 09 0b 00 00 00 5a a4 01 00 16 00 00 01 00 00 00 59 00 00 00 15 00 00 00 30 00 00 00 5c 00 00 00 6d 00 00 00 02 } //0a 00 
		$a_01_1 = {57 17 a2 09 09 0b 00 00 00 5a a4 01 00 16 00 00 01 00 00 00 57 00 00 00 15 00 00 00 30 00 00 00 5d 00 00 00 6d 00 00 00 02 } //01 00 
		$a_81_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_5 = {41 6e 6f 74 68 65 72 } //00 00  Another
	condition:
		any of ($a_*)
 
}