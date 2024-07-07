
rule Trojan_BAT_Remcos_ARS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 03 01 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 19 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARS_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0b 06 8e 69 17 59 0c 38 16 00 00 00 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARS_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 16 0c 2b 46 03 08 03 8e 69 5d 1b 59 1b 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 01 00 00 0a 03 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARS_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 22 2b 4a 00 11 22 11 04 5d 13 23 11 22 17 58 11 04 5d 13 24 07 11 24 91 20 00 01 00 00 58 13 25 07 11 23 91 13 26 11 26 08 11 22 1f 16 5d 91 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARS_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d 90 01 01 00 00 01 0a 16 0b 38 90 01 01 00 00 00 06 07 02 07 91 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARS_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 7e 01 00 00 04 07 6f 90 01 03 0a 00 7e 01 00 00 04 18 6f 90 01 03 0a 00 02 05 03 04 16 28 90 01 03 06 0c 2b 00 08 2a 90 00 } //2
		$a_01_1 = {73 61 6c 61 6d 61 6e 63 61 } //1 salamanca
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Remcos_ARS_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 38 3f 00 00 00 28 90 01 03 06 75 01 00 00 1b 28 90 01 03 0a 0b d0 01 00 00 01 28 90 01 03 0a 72 01 00 00 70 28 90 01 03 0a 07 14 6f 90 01 03 0a 75 02 00 00 1b 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARS_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 20 00 11 0a 11 0f 8f 90 01 01 00 00 01 25 47 11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 11 0f 17 58 13 0f 11 0f 11 0a 8e 69 90 00 } //2
		$a_03_1 = {2b 21 00 11 09 11 08 11 0d 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 11 0d 18 58 13 0d 11 0d 11 08 6f 90 01 01 00 00 0a fe 04 13 0e 11 0e 2d ce 90 00 } //2
		$a_01_2 = {57 00 61 00 67 00 67 00 65 00 72 00 41 00 70 00 70 00 2e 00 65 00 78 00 65 00 } //1 WaggerApp.exe
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}