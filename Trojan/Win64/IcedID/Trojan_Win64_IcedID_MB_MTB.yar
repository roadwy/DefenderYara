
rule Trojan_Win64_IcedID_MB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 04 24 ff c0 eb d1 eb 22 48 8b 44 24 08 48 ff c0 3a ed 74 56 88 08 48 8b 04 24 3a c9 74 28 48 ff c8 48 89 44 24 30 eb 5a } //05 00 
		$a_01_1 = {79 67 73 66 61 62 61 79 75 73 66 6a 6e 61 73 66 6b 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 51 5a 44 7a 76 50 45 54 6e } //01 00 
		$a_01_1 = {44 6c 6c 4d 61 69 6e } //01 00 
		$a_01_2 = {47 63 67 71 43 47 46 65 49 } //01 00 
		$a_01_3 = {4c 71 76 46 6e 4e 4b 70 4e } //01 00 
		$a_01_4 = {75 43 75 62 64 4c 6a 78 } //01 00 
		$a_01_5 = {69 4a 62 61 53 48 65 46 31 34 67 78 4a 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 69 73 62 61 64 79 75 67 61 75 73 62 64 6a 61 73 79 75 64 6a 61 73 } //01 00 
		$a_01_1 = {45 54 50 43 41 6e 57 72 42 63 69 } //01 00 
		$a_01_2 = {49 50 77 55 41 51 49 78 59 4a 63 43 6a } //01 00 
		$a_01_3 = {49 6b 48 68 75 44 65 79 4a 4f 4c 64 7a 63 } //01 00 
		$a_01_4 = {51 7a 4d 51 45 44 44 6c 6f 54 76 6d 72 } //01 00 
		$a_01_5 = {77 44 70 5a 4f 62 77 74 63 58 65 70 52 44 48 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MB_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {08 48 89 74 70 b7 45 89 44 24 18 55 03 e6 57 48 8b ec 48 83 b8 c7 49 8b f9 4d 8b f1 ed b8 1f 5a } //03 00 
		$a_01_1 = {30 48 3b f9 26 ac 8a 42 40 48 03 c1 1c 9c f9 72 05 48 8b 12 bf 79 49 85 c9 0f 84 f4 54 a7 01 4c } //03 00 
		$a_01_2 = {8b c0 4c 63 86 ef 98 83 e2 03 48 03 96 24 e1 03 48 2b c2 48 37 6f 40 0f b6 04 1a 44 5b 11 45 0d } //01 00 
		$a_81_3 = {69 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MB_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {45 6e 74 72 79 50 6f 69 6e 74 31 } //03 00 
		$a_81_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //03 00 
		$a_81_2 = {6c 74 67 63 68 68 64 72 6b } //03 00 
		$a_81_3 = {63 73 78 75 67 70 68 72 62 77 71 70 73 71 6e 6d } //03 00 
		$a_81_4 = {52 65 67 4f 70 65 6e 4b 65 79 54 72 61 6e 73 61 63 74 65 64 57 } //03 00 
		$a_81_5 = {53 77 69 74 63 68 54 6f 54 68 72 65 61 64 } //03 00 
		$a_81_6 = {49 6e 69 74 4e 65 74 77 6f 72 6b 41 64 64 72 65 73 73 43 6f 6e 74 72 6f 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MB_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 44 61 72 67 72 52 45 45 72 58 6c 4d 4a 5a 75 71 54 } //02 00 
		$a_01_1 = {63 61 6e 67 6f 5f 61 74 74 72 5f 6c 65 74 74 65 72 5f 73 70 61 63 69 6e 67 5f 6e 65 77 } //02 00 
		$a_01_2 = {63 61 6e 67 6f 5f 61 74 74 72 5f 6c 69 73 74 5f 69 6e 73 65 72 74 } //02 00 
		$a_01_3 = {63 61 6e 67 6f 5f 63 61 69 72 6f 5f 63 6f 6e 74 65 78 74 5f 73 65 74 5f 66 6f 6e 74 5f 6f 70 74 69 6f 6e 73 } //02 00 
		$a_01_4 = {63 61 6e 67 6f 5f 6c 61 79 6f 75 74 5f 73 65 74 5f 61 75 74 6f 5f 64 69 72 } //01 00 
		$a_01_5 = {69 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}