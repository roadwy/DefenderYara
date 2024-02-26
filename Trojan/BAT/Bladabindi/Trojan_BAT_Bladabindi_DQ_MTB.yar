
rule Trojan_BAT_Bladabindi_DQ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 03 07 03 6f 90 01 03 0a 5d 17 58 28 90 01 03 0a 28 90 01 03 0a 59 0c 06 08 28 90 01 03 0a 0d 12 03 28 90 01 03 0a 28 90 01 03 0a 0a 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 02 16 fe 01 13 04 11 04 2d b0 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {52 53 4d 5f 44 65 63 72 79 70 74 } //01 00  RSM_Decrypt
		$a_81_3 = {56 69 67 65 6e 65 72 65 44 65 63 72 79 70 74 } //00 00  VigenereDecrypt
	condition:
		any of ($a_*)
 
}