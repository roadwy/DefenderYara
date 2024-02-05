
rule Trojan_Win32_Guloader_RPO_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 4f 00 4c 00 46 00 42 00 45 00 52 00 52 00 49 00 45 00 53 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_1 = {63 00 72 00 6f 00 63 00 6b 00 65 00 74 00 69 00 6e 00 67 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_2 = {43 00 41 00 4c 00 43 00 49 00 46 00 55 00 47 00 41 00 4c 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_01_3 = {46 00 75 00 6e 00 6e 00 65 00 64 00 32 00 34 00 31 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_4 = {63 00 6c 00 72 00 65 00 74 00 77 00 72 00 63 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_5 = {46 00 6f 00 72 00 75 00 72 00 65 00 6e 00 69 00 6e 00 67 00 31 00 33 00 32 00 } //01 00 
		$a_01_6 = {56 00 69 00 67 00 64 00 69 00 33 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 } //01 00 
		$a_01_7 = {44 00 65 00 6c 00 65 00 74 00 65 00 44 00 43 00 } //01 00 
		$a_01_8 = {47 00 65 00 74 00 46 00 69 00 6c 00 65 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 41 00 } //01 00 
		$a_01_9 = {47 00 65 00 74 00 43 00 61 00 72 00 65 00 74 00 42 00 6c 00 69 00 6e 00 6b 00 54 00 69 00 6d 00 65 00 } //01 00 
		$a_01_10 = {43 00 72 00 79 00 70 00 74 00 44 00 65 00 73 00 74 00 72 00 6f 00 79 00 48 00 61 00 73 00 68 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPO_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 1c 10 83 ff 2e 83 fa 43 9b db e2 66 0f fa fa db e3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPO_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d2 66 0f d8 c4 0f 69 cd d9 e1 eb 19 } //01 00 
		$a_01_1 = {09 14 08 66 0f 74 f8 66 0f eb ea d9 c9 d8 d7 eb 13 } //00 00 
	condition:
		any of ($a_*)
 
}