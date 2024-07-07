
rule Trojan_Win32_Guloader_RPX_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6c 65 73 73 6f 72 73 5c 53 57 49 46 54 4e 45 53 53 5c 47 61 74 68 65 72 65 64 5c 53 61 6e 64 76 61 61 6e 65 72 65 6e 2e 6c 6e 6b } //1 Colessors\SWIFTNESS\Gathered\Sandvaaneren.lnk
		$a_01_1 = {55 6e 72 65 70 6f 72 74 6f 72 69 61 6c 2e 42 52 4e } //1 Unreportorial.BRN
		$a_01_2 = {4f 74 61 72 69 69 64 61 65 2e 48 79 70 } //1 Otariidae.Hyp
		$a_01_3 = {69 6e 64 68 6f 6c 64 73 6d 73 73 69 67 65 2e 46 4f 52 } //1 indholdsmssige.FOR
		$a_01_4 = {55 6e 62 65 64 69 6e 6e 65 64 } //1 Unbedinned
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 74 76 69 73 65 72 5c 46 6f 72 73 6b 6e 69 6e 67 73 6d 69 6c 6a 5c 53 74 6f 6c 65 6c 69 6b 65 } //1 Software\Bortviser\Forskningsmilj\Stolelike
		$a_01_1 = {4d 61 73 6b 69 6e 73 6b 72 69 76 65 72 73 6b 65 72 6e 65 73 } //1 Maskinskriverskernes
		$a_01_2 = {47 6f 6f 64 74 65 6d 70 65 72 65 64 6e 65 73 73 5c 52 65 6e 64 65 74 73 } //1 Goodtemperedness\Rendets
		$a_01_3 = {46 6f 72 73 6b 65 6c 6c 69 67 74 } //1 Forskelligt
		$a_01_4 = {44 69 67 74 65 72 6b 6f 6c 6c 65 6b 74 69 76 65 74 73 } //1 Digterkollektivets
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 6c 00 69 00 6e 00 63 00 68 00 65 00 5c 00 46 00 6f 00 72 00 74 00 61 00 62 00 65 00 } //1 Software\Malinche\Fortabe
		$a_01_1 = {42 00 69 00 61 00 6e 00 63 00 61 00 5c 00 56 00 6d 00 6d 00 65 00 6c 00 69 00 67 00 65 00 5c 00 41 00 61 00 6e 00 64 00 65 00 6c 00 69 00 67 00 67 00 72 00 } //1 Bianca\Vmmelige\Aandeliggr
		$a_01_2 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 50 00 72 00 6f 00 6c 00 65 00 74 00 61 00 72 00 69 00 61 00 6e 00 5c 00 57 00 69 00 63 00 68 00 36 00 30 00 5c 00 41 00 6c 00 66 00 61 00 6b 00 69 00 } //1 Uninstall\Proletarian\Wich60\Alfaki
		$a_01_3 = {6d 00 69 00 63 00 72 00 6f 00 6d 00 65 00 72 00 69 00 74 00 69 00 63 00 2e 00 69 00 6e 00 69 00 } //1 micromeritic.ini
		$a_01_4 = {53 00 70 00 65 00 61 00 72 00 73 00 6d 00 65 00 6e 00 2e 00 4c 00 65 00 61 00 } //1 Spearsmen.Lea
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 1c 10 d9 f2 dd e1 0f 6f df 0f e8 fc eb 2b 26 0b 1e 01 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}