
rule Trojan_BAT_CryptInject_MI_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0c 06 00 28 1d 00 00 0a 72 aa d7 06 70 28 1e 00 00 0a 6f 1f 00 00 0a 08 28 57 00 00 0a 6f 58 00 00 0a 26 07 17 58 0b 07 73 1c 00 00 0a 1f 0a 1f 14 6f 20 00 00 0a 31 a3 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {4b 69 6c 6c 50 72 6f 63 65 73 73 41 6e 64 43 68 69 6c 64 72 65 6e } //01 00 
		$a_01_3 = {72 65 6d 6f 74 65 50 6f 72 74 } //01 00 
		$a_01_4 = {44 65 73 74 72 6f 79 70 75 62 6c 69 63 44 61 74 61 } //01 00 
		$a_01_5 = {50 6f 73 74 4d 65 73 73 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}