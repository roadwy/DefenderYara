
rule Trojan_BAT_Remcos_ARO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 02 06 03 17 59 28 90 01 01 00 00 06 0b 02 06 03 28 90 01 01 00 00 06 0c 02 07 06 8e 69 58 28 90 01 01 00 00 2b 08 07 59 06 8e 69 59 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 06 00 00 04 02 7e 06 00 00 04 02 91 7e 05 00 00 04 7e 1d 00 00 04 1f 7f 7e 1d 00 00 04 1f 7f 91 02 60 20 a0 00 00 00 5f 9c 59 7e 07 00 00 04 59 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 1e 00 00 0a 0b 73 1f 00 00 0a 0c 07 16 73 20 00 00 0a 73 21 00 00 0a 0d 09 08 6f 90 01 03 0a de 0a 09 2c 06 09 6f 90 01 03 0a dc 08 6f 90 01 03 0a 13 04 de 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 15 00 06 08 06 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 } //01 00 
		$a_03_1 = {a2 25 1a 11 18 a2 25 1b 72 90 01 03 70 a2 25 1c 11 0e a2 25 1d 11 08 a2 25 1e 11 0d a2 25 1f 09 11 13 a2 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 02 28 90 01 03 0a 0c dd 08 00 00 00 26 14 0d dd 33 00 00 00 73 e8 00 00 0a 13 04 08 73 e9 00 00 0a 13 05 11 05 11 04 06 07 6f 90 01 03 0a 16 73 eb 00 00 0a 13 06 11 06 90 00 } //01 00 
		$a_01_1 = {48 00 75 00 69 00 64 00 54 00 65 00 61 00 63 00 } //00 00  HuidTeac
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 01 2a 00 38 00 00 00 00 00 72 51 00 00 70 28 90 01 03 06 13 00 38 00 00 00 00 28 90 00 } //01 00 
		$a_03_1 = {02 8e 69 17 59 13 01 20 01 00 00 00 7e 61 04 00 04 7b b5 04 00 04 39 90 01 03 ff 26 20 01 00 00 00 38 90 01 03 ff 11 03 17 58 13 03 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {14 0a 38 17 00 00 00 00 72 93 00 00 70 28 90 01 03 06 0a dd 09 00 00 00 26 dd 00 00 00 00 06 2c e6 06 2a 90 00 } //01 00 
		$a_01_1 = {73 29 00 00 0a 0a 02 28 06 00 00 2b 6f 2b 00 00 0a 0b 38 0e 00 00 00 07 6f 2c 00 00 0a 0c 06 08 6f 2d 00 00 0a 07 6f 2e 00 00 0a 2d ea } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 00 06 6f b6 00 00 0a 0c 2b 1e 12 02 28 b7 00 00 0a 0d 09 6f b5 00 00 06 16 fe 01 13 04 11 04 2c 07 09 6f b8 00 00 06 00 12 02 } //01 00 
		$a_01_1 = {0a 2b 1d 12 00 28 b7 00 00 0a 0b 07 6f b5 00 00 06 16 fe 01 0c 08 2c 08 07 02 6f b7 00 00 06 00 12 00 28 b8 00 00 0a 2d da } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARO_MTB_9{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 00 07 13 07 16 13 08 2b 43 11 07 11 08 9a 0d 00 09 6f 90 01 03 0a 72 a5 00 00 70 6f 90 01 03 0a 16 fe 01 13 09 11 09 2d 1c 00 12 02 08 8e 69 17 58 28 90 01 03 2b 00 08 08 8e 69 17 59 09 6f 90 01 03 0a a2 00 00 11 08 17 58 13 08 11 08 11 07 8e 69 fe 04 13 09 11 09 2d af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}