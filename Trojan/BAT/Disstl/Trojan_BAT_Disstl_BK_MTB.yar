
rule Trojan_BAT_Disstl_BK_MTB{
	meta:
		description = "Trojan:BAT/Disstl.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 8e 69 1f 0f 59 8d 90 01 04 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 90 01 04 1f 10 8d 90 01 04 0c 07 8e 69 08 8e 69 59 8d 90 01 04 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 90 00 } //01 00 
		$a_03_1 = {07 16 09 16 07 8e 69 08 8e 69 59 28 90 01 04 73 90 01 04 13 04 28 90 01 04 11 04 03 06 14 09 08 6f 90 01 04 6f 90 01 04 13 05 11 05 13 06 de 06 90 00 } //01 00 
		$a_01_2 = {44 65 63 72 79 70 74 57 69 74 68 4b 65 79 } //01 00  DecryptWithKey
		$a_01_3 = {53 74 65 61 6c 50 61 73 73 77 6f 72 64 73 } //01 00  StealPasswords
		$a_81_4 = {45 72 72 6f 72 20 69 6e 20 41 6e 74 69 20 44 65 62 75 67 2c 20 43 68 65 63 6b 20 44 65 62 75 67 } //01 00  Error in Anti Debug, Check Debug
		$a_81_5 = {76 69 72 74 75 61 6c 62 6f 78 } //01 00  virtualbox
		$a_81_6 = {68 74 74 70 73 3a 2f 2f 69 70 34 2e 73 65 65 69 70 2e 6f 72 67 } //01 00  https://ip4.seeip.org
		$a_81_7 = {55 6e 61 62 6c 65 20 74 6f 20 64 65 63 72 79 70 74 } //01 00  Unable to decrypt
		$a_81_8 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //00 00  encrypted_key
	condition:
		any of ($a_*)
 
}