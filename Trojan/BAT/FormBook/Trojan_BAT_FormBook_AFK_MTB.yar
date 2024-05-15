
rule Trojan_BAT_FormBook_AFK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 2b 28 0a 2b f1 0b 2b f8 02 50 06 91 19 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 90 00 } //01 00 
		$a_01_1 = {4d 61 69 6e 53 74 6f 72 65 46 75 6e 63 74 69 6f 6e 61 6c 69 74 79 2e 4d 6f 64 65 6c 73 } //00 00  MainStoreFunctionality.Models
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFK_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 90 01 01 00 00 06 d2 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 90 01 01 00 00 06 d2 59 20 00 01 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFK_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 13 04 16 13 05 2b 3c 11 04 11 05 9a 0c 08 6f 90 01 01 00 00 0a 04 28 90 01 01 00 00 0a 2c 22 72 90 01 01 00 00 70 08 72 90 01 01 00 00 70 18 8d 90 01 01 00 00 01 13 06 11 06 16 03 a2 11 06 28 90 01 01 00 00 06 0d de 10 11 05 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFK_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 2e 11 05 11 06 9a 13 07 00 11 04 6f 90 01 01 01 00 0a 11 07 28 90 01 01 00 00 0a 13 08 11 08 2c 0b 00 06 07 11 04 a2 07 17 58 90 00 } //01 00 
		$a_03_1 = {0d 2b 48 00 06 09 06 8e 69 5d 06 09 06 8e 69 5d 91 07 09 07 6f 90 01 01 01 00 0a 5d 6f 90 01 01 02 00 0a 61 28 90 01 01 00 00 0a 06 09 17 58 06 8e 69 5d 91 28 90 01 01 02 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 02 00 0a 9c 00 09 15 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFK_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 16 ac 01 00 13 04 2b 19 00 06 11 04 06 8e 69 5d 02 06 11 04 28 90 01 03 06 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d d9 90 00 } //01 00 
		$a_01_1 = {55 00 6e 00 63 00 6c 00 65 00 4e 00 61 00 62 00 65 00 65 00 6c 00 73 00 42 00 61 00 6b 00 65 00 72 00 79 00 } //01 00  UncleNabeelsBakery
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //00 00  System.Reflection.Assembly
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFK_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 0a 11 09 6f 90 01 03 0a 13 0b 16 13 0c 11 05 11 08 9a 72 55 04 00 70 28 90 01 03 0a 13 0d 11 0d 2c 0d 00 12 0b 28 90 01 03 0a 13 0c 00 2b 42 11 05 11 08 9a 72 59 04 00 70 28 90 01 03 0a 13 0e 11 0e 2c 0d 00 12 0b 28 90 01 03 0a 13 0c 00 2b 20 11 05 11 08 9a 72 5d 04 00 70 28 90 01 03 0a 13 0f 11 0f 2c 0b 00 12 0b 28 90 01 03 0a 13 0c 00 07 11 0c 90 00 } //01 00 
		$a_01_1 = {43 00 53 00 44 00 4c 00 5f 00 51 00 4c 00 4e 00 53 00 5f 00 51 00 4c 00 4c 00 55 00 4f 00 4e 00 47 00 } //00 00  CSDL_QLNS_QLLUONG
	condition:
		any of ($a_*)
 
}