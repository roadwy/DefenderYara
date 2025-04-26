
rule Trojan_BAT_Remcos_ARC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 18 5b 08 06 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 06 18 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Remcos_ARC_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 01 02 11 01 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 20 06 00 00 00 7e ?? 01 00 04 7b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARC_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 04 00 00 04 28 32 00 00 0a 04 6f 33 00 00 0a 6f 34 00 00 0a 0a 7e 03 00 00 04 06 6f 35 00 00 0a 00 7e 03 00 00 04 18 6f 36 00 00 0a 00 02 03 05 28 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Remcos_ARC_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 16 0c 2b 63 03 08 03 8e 69 5d 1f 20 59 1f 20 58 03 08 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 61 28 ?? ?? ?? 0a 03 08 20 8a 10 00 00 58 20 89 10 00 00 59 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARC_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 11 04 11 06 11 08 91 6f ?? 00 00 0a 11 08 17 58 13 08 11 08 03 32 ea } //1
		$a_03_1 = {16 13 08 2b 34 09 11 08 8f ?? 00 00 01 25 47 11 04 11 08 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 11 04 1f 1f 5a 09 11 08 91 58 20 00 01 00 00 5d 13 04 11 08 17 58 13 08 11 08 09 8e 69 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}