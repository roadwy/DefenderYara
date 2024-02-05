
rule Trojan_Win64_IcedID_DG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {0f 94 c2 0f 94 44 24 06 41 b9 ca 48 06 3d 41 b8 ba d4 b5 2d b8 ba d4 b5 2d 41 0f 44 c1 83 f9 0a 0f 9c 44 24 07 0f 9c c1 41 0f 4d c0 30 d1 41 0f 45 c1 } //03 00 
		$a_81_1 = {4a 74 6d 78 72 64 70 6a 72 6f 55 61 69 62 72 77 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {71 61 65 6f 4d 2e 64 6c 6c } //01 00 
		$a_01_1 = {4c 53 45 32 66 37 58 38 59 44 51 } //01 00 
		$a_01_2 = {55 61 43 59 35 6c 4b 77 6a 49 76 } //01 00 
		$a_01_3 = {6a 68 62 66 67 79 75 6a 67 68 66 67 64 } //01 00 
		$a_01_4 = {67 41 41 44 59 75 38 5a 47 } //01 00 
		$a_01_5 = {58 4b 34 54 4e 38 43 36 4a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DG_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 84 24 90 00 00 00 48 8b 84 24 90 00 00 00 48 8b 40 18 48 89 84 24 80 00 00 00 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 b8 08 00 00 00 48 6b c0 01 48 8b 8c 24 80 00 00 00 48 8b 44 01 08 48 89 44 24 50 eb 17 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DG_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //03 00 
		$a_81_1 = {41 66 74 70 72 6f 71 73 43 68 70 70 61 6f 71 74 55 63 61 64 64 67 63 78 } //03 00 
		$a_81_2 = {46 66 61 71 78 6a 71 78 74 46 7a 6c 6b 6a 66 78 68 6b 6d 62 6b 64 6b } //03 00 
		$a_81_3 = {4f 68 61 78 65 72 6f 41 73 65 76 76 71 61 64 } //03 00 
		$a_81_4 = {5a 67 62 67 6f 66 6e 56 76 78 74 73 79 61 70 71 78 62 67 } //03 00 
		$a_81_5 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 4d 70 44 72 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DG_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 83 c3 3f 8a 53 01 8a 0b 8a 43 ff 48 8d 5b 03 c0 e2 03 80 e1 07 0a d1 24 07 c0 e2 03 0a d0 43 88 14 08 } //00 00 
	condition:
		any of ($a_*)
 
}