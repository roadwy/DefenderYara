
rule Trojan_Win32_Guloader_RPP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 1c 38 ff 45 38 ff 4d 38 fc 83 c7 04 ff 45 38 ff 4d 38 83 04 24 00 81 ff ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPP_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f dc e5 ff 34 32 [0-20] 90 13 [0-20] 81 34 24 [0-20] 8f 04 30 [0-20] 83 de [0-20] 90 13 [0-20] 83 d6 ?? 0f 8d ?? ff ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPP_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {48 69 6e 64 75 69 73 74 69 73 6b 5c 41 63 74 69 6e 69 6e 65 5c 45 6e 70 75 6b 6c 65 74 5c 55 6e 62 61 73 74 61 72 64 69 7a 65 64 } //1 Hinduistisk\Actinine\Enpuklet\Unbastardized
		$a_01_1 = {55 6e 61 63 63 75 73 74 6f 6d 65 64 5c 4e 69 6e 6e 69 } //1 Unaccustomed\Ninni
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 47 61 77 6b 73 } //1 Software\Gawks
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 75 64 62 75 64 } //1 Software\udbud
		$a_01_4 = {64 69 63 74 79 6f 74 61 5c 53 74 69 70 6c 65 } //1 dictyota\Stiple
		$a_01_5 = {56 69 74 61 6c 69 7a 65 64 5c 54 6f 72 76 65 64 61 67 65 } //1 Vitalized\Torvedage
		$a_01_6 = {53 61 6d 74 69 64 65 6e } //1 Samtiden
		$a_01_7 = {57 68 69 70 63 72 61 63 6b 65 72 } //1 Whipcracker
		$a_01_8 = {53 75 6c 70 68 6f 63 79 61 6e 61 74 65 2e 4b 6f 6c } //1 Sulphocyanate.Kol
		$a_01_9 = {43 65 6e 74 72 61 6c 66 6f 72 65 6e 69 6e 67 65 72 73 2e 6d 75 74 } //1 Centralforeningers.mut
		$a_01_10 = {68 6b 6c 69 6e 67 65 6e 2e 69 6e 69 } //1 hklingen.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule Trojan_Win32_Guloader_RPP_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 00 79 00 73 00 6b 00 65 00 72 00 73 00 2e 00 4d 00 69 00 6c 00 } //1 Lyskers.Mil
		$a_01_1 = {55 00 6e 00 64 00 6c 00 62 00 2e 00 41 00 66 00 66 00 33 00 32 00 } //1 Undlb.Aff32
		$a_01_2 = {42 00 65 00 73 00 61 00 61 00 6e 00 69 00 6e 00 67 00 65 00 6e 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 Besaaningens.dll
		$a_01_3 = {50 00 72 00 69 00 6e 00 74 00 65 00 72 00 6d 00 61 00 6e 00 75 00 61 00 6c 00 5c 00 43 00 61 00 77 00 71 00 75 00 61 00 77 00 5c 00 43 00 61 00 6c 00 69 00 70 00 68 00 73 00 32 00 } //1 Printermanual\Cawquaw\Caliphs2
		$a_01_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 70 00 69 00 6e 00 6f 00 66 00 66 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 74 00 61 00 73 00 74 00 5c 00 4e 00 61 00 76 00 69 00 67 00 65 00 72 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 } //1 Software\Spinoff\Systemtast\Navigeringernes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPP_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 4a 4a 09 3c 01 de e0 de f7 eb 3f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}