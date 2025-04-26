
rule Trojan_BAT_DarkComet_ADK_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 1f 06 08 8f 0c 00 00 01 25 71 0c 00 00 01 07 08 07 8e 69 5d 91 61 d2 81 0c 00 00 01 08 17 58 0c 08 06 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 1f 26 9c 11 05 17 20 dc 00 00 00 9c 11 05 18 20 ff 00 00 00 9c 11 05 19 16 9c 11 05 1a 20 ad 00 00 00 9c 11 05 1b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 19 02 06 02 06 91 03 06 7e ?? 00 00 04 5d 91 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 03 8e b7 17 da 13 04 0d 2b 24 03 09 03 09 91 ?? ?? ?? 8e b7 5d 91 09 06 d6 07 8e b7 d6 1d 5f 64 d2 20 ff 00 00 00 5f b4 61 9c 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 02 50 06 02 50 06 91 7e 01 00 00 04 06 7e 01 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 02 50 8e 69 32 d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 03 06 72 ?? 00 00 70 6f ?? 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 25 08 09 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 1f 67 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 07 17 d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_8{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 02 8e b7 17 da 13 06 13 05 2b 29 09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_9{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 20 19 15 15 28 ?? 00 00 0a 1f 0a 13 07 1b 07 15 6a 16 28 ?? 00 00 0a 1f 0b 13 07 17 8d ?? 00 00 01 13 04 11 04 16 1b 9e 11 04 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_10{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 31 02 08 8f 11 00 00 01 25 71 11 00 00 01 07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 11 00 00 01 08 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_11{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0d 09 0e 04 2f 03 09 10 04 16 0a 2b 0e 05 06 d3 18 5a 58 08 06 93 53 06 17 58 0a 06 0e 04 32 ed } //1
		$a_01_1 = {16 0a 2b 0b 07 06 03 06 58 47 9c 06 17 58 0a 06 04 32 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_12{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 d1 0d 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e b7 fe 04 13 04 11 04 2d c9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_13{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0d 13 0a 2b 56 11 09 17 d6 20 00 01 00 00 5d 13 09 07 11 05 11 09 91 d6 20 00 01 00 00 5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 02 50 11 0a 02 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6 13 0a 11 0a 11 0d 31 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_14{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1e 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 06 08 6f ?? 00 00 0a d2 61 d2 9c 08 17 58 0c 08 06 } //2
		$a_03_1 = {16 13 05 2b 1d 11 04 11 05 91 0c 07 08 13 06 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 07 11 07 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_15{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 08 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 06 2b 0a 11 0a 16 8f ?? ?? ?? 01 13 06 11 05 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 07 2b 0a 11 0a 16 8f ?? ?? ?? 01 13 07 11 06 d3 11 07 d3 08 8e 69 11 05 8e 69 28 ?? ?? ?? 06 13 04 16 e0 13 07 16 e0 13 06 00 11 04 16 32 0a 11 05 8e 69 11 04 fe 04 2b 01 17 13 0b 11 0b 2d 87 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_16{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 02 50 8e b7 17 da 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5 } //2
		$a_01_1 = {54 00 68 00 65 00 45 00 6c 00 65 00 76 00 61 00 74 00 6f 00 72 00 2e 00 74 00 78 00 74 00 } //1 TheElevator.txt
		$a_01_2 = {53 00 7a 00 43 00 57 00 79 00 45 00 52 00 4f 00 77 00 4b 00 6a 00 6a 00 4c 00 54 00 67 00 49 00 } //1 SzCWyEROwKjjLTgI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_DarkComet_ADK_MTB_17{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 da 13 06 13 05 2b 34 09 11 05 02 11 05 91 11 04 61 08 07 91 61 9c 08 28 ?? ?? ?? 0a 00 07 08 8e b7 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05 00 07 17 d6 } //2
		$a_01_1 = {6f 00 6d 00 65 00 75 00 73 00 65 00 67 00 75 00 6e 00 64 00 6f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 omeusegundo.Properties.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}