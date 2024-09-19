
rule Trojan_BAT_Heracles_AHL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 4e 00 00 01 28 ?? ?? ?? 06 74 01 00 00 1b 28 ?? ?? ?? 06 17 2d 03 26 de 06 0a 2b fb 26 de d0 06 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AHL_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 8b 00 00 70 28 ?? ?? ?? 06 1b 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 } //1
		$a_01_1 = {02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Heracles_AHL_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 33 11 08 11 09 9a 13 0a 11 0a 73 ?? 01 00 0a 13 0b 00 11 0b 6f ?? 01 00 0a 00 de 10 25 28 ?? 00 00 0a 13 0c 00 28 ?? 00 00 0a de 00 00 00 11 09 17 d6 13 09 11 09 11 08 8e 69 } //2
		$a_01_1 = {43 00 68 00 65 00 63 00 6b 00 58 00 53 00 45 00 4f 00 } //1 CheckXSEO
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Heracles_AHL_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 72 74 68 41 6d 65 72 69 63 61 55 70 64 61 74 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 NorthAmericaUpdate.Properties.Resources
		$a_01_1 = {62 63 33 38 66 35 65 33 2d 33 61 35 31 2d 34 33 63 35 2d 38 39 37 61 2d 31 37 38 32 32 38 64 37 66 34 32 30 } //1 bc38f5e3-3a51-43c5-897a-178228d7f420
		$a_01_2 = {4e 00 6f 00 72 00 74 00 68 00 41 00 6d 00 65 00 72 00 69 00 63 00 61 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 NorthAmericaUpdate.exe
		$a_01_3 = {55 00 70 00 64 00 61 00 74 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 4a 00 61 00 76 00 61 00 } //1 Update from Java
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}