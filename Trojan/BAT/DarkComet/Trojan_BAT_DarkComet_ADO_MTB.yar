
rule Trojan_BAT_DarkComet_ADO_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 02 50 11 0a 02 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADO_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 18 5a 03 8e 69 58 0a 2b 35 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 0b 07 20 00 01 00 00 5d d2 0c 02 06 02 8e 69 5d 08 9c 06 15 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADO_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 13 05 16 0c 06 74 ?? 00 00 01 08 1f 64 d6 17 d6 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 1b 0a 07 06 11 05 1f 64 6f ?? 00 00 0a 13 06 11 06 16 2e 0e 11 05 11 06 d6 13 05 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_ADO_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {1e 9c 11 05 1f 0e 1f 22 9c 11 05 1f 0f 1f 3c 9c 11 05 73 ?? 00 00 0a 0b 11 04 07 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 07 1f 10 6f } //2
		$a_01_1 = {62 00 75 00 6d 00 6d 00 79 00 62 00 75 00 6d 00 62 00 75 00 6d 00 } //1 bummybumbum
		$a_01_2 = {48 00 61 00 72 00 64 00 43 00 6f 00 72 00 65 00 44 00 4c 00 4c 00 2e 00 44 00 69 00 6d 00 44 00 6f 00 6d 00 } //1 HardCoreDLL.DimDom
		$a_01_3 = {64 00 75 00 6d 00 6d 00 6d 00 79 00 64 00 75 00 6d 00 64 00 75 00 6d 00 } //1 dummmydumdum
		$a_01_4 = {65 00 72 00 69 00 63 00 73 00 73 00 6f 00 6e 00 } //1 ericsson
		$a_01_5 = {53 00 61 00 79 00 48 00 61 00 72 00 64 00 43 00 6f 00 72 00 65 00 54 00 72 00 6f 00 6f 00 6c 00 6c 00 } //1 SayHardCoreTrooll
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}