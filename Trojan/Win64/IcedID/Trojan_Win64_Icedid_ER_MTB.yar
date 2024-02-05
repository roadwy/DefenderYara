
rule Trojan_Win64_Icedid_ER_MTB{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 8b 43 38 48 63 93 c0 02 00 00 48 8b 4b 10 0f b6 14 0a 42 32 14 18 48 8b 43 60 41 88 14 03 48 81 7b 20 45 3b 00 00 73 12 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {48 f7 fa 49 ff c0 49 83 de 1e 48 1d 90 17 00 00 4c 13 e8 48 f7 c4 e2 12 00 00 c8 45 00 00 83 04 24 01 8b 04 24 } //01 00 
		$a_01_1 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_3{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_1 = {51 6f 78 67 46 48 } //01 00 
		$a_01_2 = {53 63 72 59 73 49 } //01 00 
		$a_01_3 = {69 62 5a 49 64 4c 67 64 } //01 00 
		$a_01_4 = {6c 4e 73 59 73 41 6f 70 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_4{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 79 75 61 73 62 62 6a 68 61 73 } //01 00 
		$a_01_1 = {53 36 43 53 66 66 39 } //01 00 
		$a_01_2 = {5a 31 61 30 6f 59 53 6d 36 } //01 00 
		$a_01_3 = {65 45 72 61 6e 76 70 } //01 00 
		$a_01_4 = {71 46 59 62 75 4c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_5{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 76 6e 4d 69 46 64 52 59 6d } //01 00 
		$a_01_1 = {42 6e 79 69 75 74 74 32 37 } //01 00 
		$a_01_2 = {45 74 32 77 38 47 41 69 75 78 } //01 00 
		$a_01_3 = {45 7a 78 64 30 50 7a 33 } //01 00 
		$a_01_4 = {4b 4b 4e 78 41 50 66 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_6{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 51 61 69 58 31 33 63 46 46 6c } //01 00 
		$a_01_1 = {54 7a 39 75 46 41 62 65 } //01 00 
		$a_01_2 = {58 36 6a 76 75 63 36 4a 5a 72 } //01 00 
		$a_01_3 = {58 77 33 53 5a 75 45 4d 58 } //01 00 
		$a_01_4 = {68 59 70 37 6f 79 49 49 67 43 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_7{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4f 41 76 68 63 70 56 41 47 68 } //02 00 
		$a_01_1 = {61 47 5a 34 54 49 77 6b 75 34 77 50 53 37 48 42 64 59 6d 33 5a 37 73 64 36 72 62 59 48 36 39 6a 45 } //01 00 
		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_3 = {52 41 43 6d 75 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_8{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 67 68 63 67 78 61 73 68 66 67 66 73 66 67 64 66 } //01 00 
		$a_01_1 = {48 76 47 34 58 45 39 70 4e 79 69 6c 4d 4c 38 77 } //01 00 
		$a_01_2 = {4d 62 31 52 4f 4c 62 6d 36 } //01 00 
		$a_01_3 = {54 32 65 44 33 61 77 6f 42 7a 41 43 43 } //01 00 
		$a_01_4 = {55 36 6b 78 4b 4a 42 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_9{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_1 = {47 68 6f 73 74 53 63 72 69 70 74 } //01 00 
		$a_01_2 = {49 6d 61 67 65 4d 61 67 69 63 6b } //01 00 
		$a_01_3 = {78 61 6b 65 70 2e 72 75 } //01 00 
		$a_01_4 = {73 76 67 55 72 6c } //01 00 
		$a_01_5 = {62 61 75 43 4d 52 2e 64 6c 6c } //01 00 
		$a_01_6 = {4f 6b 70 76 56 53 66 64 6b 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_ER_MTB_10{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8d 50 ff 0f af d0 f7 d2 83 ca fe 83 fa ff 0f 94 c0 41 83 f9 0a 0f 9c c1 30 c1 41 ba a1 e6 40 89 b8 e3 0e 41 e1 41 0f 45 c2 83 fa ff 0f 94 44 24 06 41 b8 e3 0e 41 e1 44 0f 45 d0 41 83 f9 0a 0f 9c 44 24 } //03 00 
		$a_81_1 = {4d 67 6b 72 76 6f 69 71 6a 68 62 72 65 6f 74 62 5a 63 66 6b 77 6a 67 6a 6e 76 6a 75 } //00 00 
	condition:
		any of ($a_*)
 
}