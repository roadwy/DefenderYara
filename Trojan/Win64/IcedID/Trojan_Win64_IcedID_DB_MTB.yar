
rule Trojan_Win64_IcedID_DB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6b 6e 74 54 46 57 66 45 5a 45 43 72 } //01 00 
		$a_01_1 = {47 61 52 6e 74 6e 62 44 50 58 53 58 68 72 46 4f 66 73 6d } //01 00 
		$a_01_2 = {49 49 49 6d 78 70 70 4f 6a 70 76 52 6d 43 6b 6c 79 47 54 } //01 00 
		$a_01_3 = {4b 6b 6e 63 75 48 4a 51 43 4a 43 77 42 62 6b } //01 00 
		$a_01_4 = {4c 6b 62 76 4e 62 7a 77 71 57 47 61 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 c1 eb 20 01 c3 81 c3 eb 14 00 00 89 df c1 ef 1f c1 fb 06 01 fb 89 df c1 e7 07 29 fb 8d 3c 03 81 c7 eb 14 00 00 01 d8 05 6a 15 } //03 00 
		$a_80_1 = {67 6c 6f 65 71 77 } //gloeqw  03 00 
		$a_80_2 = {67 77 78 62 6f 70 77 } //gwxbopw  03 00 
		$a_80_3 = {6a 6c 78 6e 65 77 } //jlxnew  03 00 
		$a_80_4 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  03 00 
		$a_80_5 = {53 65 6e 64 4d 65 73 73 61 67 65 57 } //SendMessageW  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {81 f9 9a d5 c9 bf 7e 2d 81 f9 bc 8b 54 f8 7e 60 81 f9 bd 8b 54 f8 0f 84 bb 00 00 00 81 f9 d6 b0 5b f8 0f 84 a9 00 00 00 81 f9 80 b1 1c 78 75 d0 e9 fd } //03 00 
		$a_80_1 = {63 72 31 2e 64 6c 6c } //cr1.dll  03 00 
		$a_80_2 = {53 79 73 74 65 6d 50 61 72 61 6d 65 74 65 72 73 49 6e 66 6f 41 } //SystemParametersInfoA  03 00 
		$a_80_3 = {53 65 6e 64 4d 65 73 73 61 67 65 41 } //SendMessageA  03 00 
		$a_80_4 = {47 65 74 43 6c 61 73 73 4e 61 6d 65 41 } //GetClassNameA  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DB_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {4e 4c 64 70 4f 57 62 55 5a 34 2e 64 6c 6c } //01 00 
		$a_01_2 = {52 51 4e 57 73 75 6e 44 63 62 } //01 00 
		$a_01_3 = {64 79 67 56 4d 75 64 6b 41 } //01 00 
		$a_01_4 = {6f 48 62 68 64 48 73 50 51 59 } //01 00 
		$a_01_5 = {79 47 46 56 4f 4e 68 62 } //01 00 
		$a_01_6 = {31 74 33 45 6f 38 2e 64 6c 6c } //01 00 
		$a_01_7 = {4c 51 79 68 73 43 64 6a 6c } //01 00 
		$a_01_8 = {53 51 63 63 44 6d 4a 6c 68 45 } //01 00 
		$a_01_9 = {56 6f 73 51 6c 42 72 58 } //01 00 
		$a_01_10 = {5a 42 43 49 52 43 79 } //00 00 
	condition:
		any of ($a_*)
 
}