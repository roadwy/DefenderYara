
rule Trojan_BAT_FormBook_AMF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 46 16 0d 2b 3a 16 13 04 2b 2c 11 07 07 09 58 08 11 04 58 6f 90 01 03 0a 13 0b 12 0b 28 90 01 03 0a 13 09 11 06 11 05 11 09 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AMF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 07 11 0c 11 06 11 0c 9a 1f 10 28 90 01 03 0a 9c 11 0c 17 58 90 00 } //01 00 
		$a_01_1 = {4d 00 61 00 69 00 6e 00 50 00 6c 00 61 00 79 00 65 00 72 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 46 00 6f 00 72 00 6d 00 } //00 00  MainPlayerManagementForm
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AMF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {5d 91 13 07 11 06 17 58 08 5d 13 08 07 11 06 91 11 07 61 13 09 07 11 08 91 13 0a 02 11 09 11 0a 28 90 01 01 00 00 06 13 0b 07 11 06 11 0b 28 90 01 01 00 00 0a 9c 00 11 06 17 58 90 00 } //01 00 
		$a_01_1 = {45 00 6d 00 75 00 4c 00 69 00 73 00 74 00 65 00 72 00 } //00 00  EmuLister
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AMF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {5d 91 0d 07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 13 04 11 04 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 05 07 08 11 05 28 90 01 01 00 00 0a 9c 08 17 58 90 00 } //01 00 
		$a_01_1 = {45 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 65 00 49 00 6e 00 66 00 6f 00 41 00 70 00 70 00 } //00 00  EmployeeInfoApp
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AMF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {25 16 09 a2 25 17 19 8d 90 01 01 00 00 01 25 16 02 7b 90 01 01 00 00 04 a2 25 17 02 7b 90 01 01 00 00 04 a2 25 18 90 00 } //02 00 
		$a_01_1 = {16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f 6f 00 00 0a 1f 10 28 70 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de } //01 00 
		$a_01_2 = {53 00 65 00 61 00 72 00 63 00 68 00 5f 00 49 00 6e 00 64 00 65 00 78 00 65 00 72 00 } //00 00  Search_Indexer
	condition:
		any of ($a_*)
 
}