
rule Trojan_BAT_FormBook_AF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 25 26 6f 90 01 03 0a 00 de 02 2b 2d 08 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 16 73 90 01 03 0a 0d 09 07 6f 90 01 03 0a 07 13 05 de 15 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {17 72 4d 00 00 70 12 00 73 2c 00 00 0a 80 03 00 00 04 06 3a 06 00 00 00 17 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 90 01 03 0a 05 03 17 58 05 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 26 0b 28 20 00 00 0a 25 26 07 16 07 8e 69 6f 21 00 00 0a 25 26 0a 28 1d 00 00 0a 25 26 06 6f 3b 00 00 0a 0c 1f 61 6a 08 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0e 11 1d 58 11 21 11 21 28 57 00 00 06 25 26 69 12 03 6f 31 00 00 06 25 26 } //01 00 
		$a_01_1 = {48 00 56 00 70 00 4f 00 4c 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {14 14 18 8d 01 00 00 01 25 16 09 74 07 00 00 01 28 90 01 03 06 17 9a a2 25 17 11 04 a2 28 90 00 } //01 00 
		$a_01_1 = {50 00 61 00 72 00 73 00 65 00 72 00 41 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 16 11 01 a2 25 13 02 14 14 17 8d 04 00 00 01 25 16 17 9c 25 } //01 00 
		$a_01_1 = {50 00 6f 00 72 00 61 00 6c 00 50 00 65 00 72 00 69 00 6c 00 5f 00 53 00 74 00 65 00 66 00 61 00 6e 00 54 00 69 00 63 00 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 91 61 28 90 01 03 0a 07 09 17 58 07 8e 69 5d 91 28 90 00 } //01 00 
		$a_01_1 = {54 00 65 00 73 00 74 00 46 00 69 00 72 00 73 00 74 00 57 00 46 00 61 00 70 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 16 09 11 04 08 11 04 9a 1f 10 28 a3 00 00 0a 9c 11 04 17 d6 13 04 00 11 04 20 00 c2 00 00 fe 04 13 06 11 06 2d db } //01 00 
		$a_01_1 = {50 00 6f 00 6b 00 65 00 6d 00 6f 00 6e 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 1a 08 11 05 07 11 05 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9 90 00 } //01 00 
		$a_01_1 = {46 00 6f 00 6c 00 64 00 65 00 72 00 54 00 6f 00 54 00 65 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 15 07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //01 00 
		$a_01_1 = {5f 00 32 00 30 00 34 00 38 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 20 00 07 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 00 09 18 58 0d 00 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d d1 90 00 } //01 00 
		$a_01_1 = {46 00 6f 00 72 00 6d 00 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 48 00 61 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 16 58 0a 2b 48 06 11 04 5d 13 06 06 11 08 5d 13 0b 07 11 06 91 13 0c 11 05 11 0b 6f 90 01 03 0a 13 0d 07 06 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 06 2b 42 00 07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 91 61 28 90 01 03 0a 07 11 06 17 58 07 8e 69 5d 91 90 00 } //01 00 
		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 54 00 6f 00 6f 00 6c 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_16{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 20 2b 28 00 11 1e 11 20 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 22 11 1f 11 22 6f 90 01 03 0a 00 11 20 18 58 13 20 00 11 20 11 1e 6f 90 01 03 0a fe 04 13 23 11 23 2d c7 90 00 } //01 00 
		$a_01_1 = {65 00 76 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 53 00 6f 00 63 00 63 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 16 13 07 2b 61 11 05 11 07 6f 90 01 03 0a 1f 77 33 06 11 04 17 59 13 04 11 05 11 07 6f 90 01 03 0a 1f 61 33 04 09 17 59 0d 11 05 11 07 6f 90 01 03 0a 1f 73 33 06 11 04 17 58 13 04 11 05 11 07 6f 90 01 03 0a 1f 64 33 04 09 17 58 0d 02 90 00 } //01 00 
		$a_01_1 = {54 00 6f 00 77 00 65 00 72 00 20 00 44 00 65 00 66 00 65 00 6e 00 73 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f 90 01 03 0a 13 0b 16 13 0c 11 05 11 08 9a 72 46 04 00 70 28 90 01 03 0a 13 0d 11 0d 2c 0d 00 12 0b 28 90 01 03 0a 13 0c 00 2b 42 11 05 11 08 9a 72 4a 04 00 70 28 90 01 03 0a 13 0e 11 0e 2c 0d 00 12 0b 28 90 01 03 0a 13 0c 00 2b 20 11 05 11 08 9a 72 4e 04 00 70 28 90 01 03 0a 13 0f 11 0f 2c 0b 00 12 0b 28 90 01 03 0a 13 0c 00 07 11 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_19{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {26 00 11 05 7b 15 00 00 04 28 90 01 03 0a 25 26 28 90 01 03 0a 25 26 6f 90 01 03 0a 00 de 05 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 48 56 70 4f 4c 2e 70 64 62 } //01 00 
		$a_01_2 = {48 00 56 00 70 00 4f 00 4c 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_20{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 2b 36 12 01 28 90 01 03 0a 0c 00 06 12 03 fe 15 05 00 00 02 12 03 12 02 28 90 01 03 0a 7d 04 00 00 04 12 03 12 02 28 90 01 03 0a 7d 05 00 00 04 09 6f 90 01 03 0a 00 00 12 01 28 90 00 } //02 00 
		$a_03_1 = {0d 2b 26 12 03 28 90 01 03 0a 13 04 00 08 07 11 04 7b 04 00 00 04 11 04 7b 05 00 00 04 8c 2a 00 00 01 6f 90 01 03 0a 26 00 12 03 28 90 00 } //01 00 
		$a_01_2 = {52 00 65 00 73 00 75 00 6d 00 65 00 46 00 6f 00 72 00 6d 00 61 00 74 00 44 00 65 00 74 00 65 00 63 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AF_MTB_21{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 21 00 00 04 25 2d 17 26 7e 20 00 00 04 fe 06 36 00 00 06 73 10 00 00 0a 25 80 21 00 00 04 0a 72 5d 01 00 70 28 90 01 03 0a 0b 06 07 6f 90 01 03 0a 0c 02 8e 69 8d 90 01 03 01 0d 08 02 16 02 8e 69 09 16 6f 90 01 03 0a 13 04 09 11 04 90 00 } //01 00 
		$a_01_1 = {41 00 6e 00 20 00 65 00 78 00 70 00 65 00 72 00 69 00 6d 00 65 00 6e 00 74 00 61 00 6c 00 20 00 77 00 65 00 62 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 74 00 68 00 61 00 74 00 20 00 75 00 73 00 65 00 73 00 20 00 69 00 6e 00 6e 00 6f 00 76 00 61 00 74 00 69 00 76 00 65 00 20 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}