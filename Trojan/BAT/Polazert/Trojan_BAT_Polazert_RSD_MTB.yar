
rule Trojan_BAT_Polazert_RSD_MTB{
	meta:
		description = "Trojan:BAT/Polazert.RSD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 2b 00 41 00 61 00 2b 00 41 00 } //01 00  A+Aa+A
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {4b 65 79 56 61 6c 75 65 50 61 69 72 } //01 00  KeyValuePair
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {52 65 61 64 42 79 74 65 } //00 00  ReadByte
	condition:
		any of ($a_*)
 
}