
rule Trojan_BAT_Quasar_AAGR_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AAGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 01 00 00 0a 0a 06 28 90 01 01 00 00 06 0b 07 02 28 90 01 01 00 00 06 0c 2b 00 08 2a 90 00 } //01 00 
		$a_01_1 = {4b 00 4d 00 45 00 56 00 74 00 52 00 7a 00 78 00 47 00 30 00 6f 00 57 00 6c 00 2f 00 76 00 4f 00 34 00 74 00 6c 00 38 00 38 00 76 00 34 00 68 00 4a 00 63 00 42 00 4e 00 49 00 7a 00 73 00 6f 00 6f 00 38 00 67 00 48 00 54 00 4b 00 4d 00 50 00 6d 00 6f 00 55 00 3d 00 } //01 00  KMEVtRzxG0oWl/vO4tl88v4hJcBNIzsoo8gHTKMPmoU=
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}