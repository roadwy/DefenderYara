
rule Trojan_Win64_IcedID_MY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {41 f7 eb 89 c8 c1 f8 90 01 01 c1 fa 90 01 01 29 c2 89 c8 44 8d 04 d2 45 01 c0 44 29 c0 4c 63 c0 46 0f b6 04 06 45 32 04 09 45 88 04 0a 44 8d 41 01 48 83 c1 01 44 39 44 24 2c 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MY_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 09 88 08 eb 90 01 01 48 8b 44 24 08 48 8b 4c 24 10 eb 90 01 01 48 8b 44 24 30 48 89 44 24 08 eb 90 01 01 8b 44 24 40 ff c8 eb 90 01 01 48 ff c0 48 89 44 24 10 eb 90 00 } //05 00 
		$a_01_1 = {47 62 68 61 6a 61 73 64 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MY_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b 55 54 4c 8b f0 48 8b c5 48 85 d2 74 90 01 01 4d 8b c6 4c 2b c5 0f 1f 84 00 00 00 00 00 0f b6 08 41 88 0c 00 48 8d 40 01 48 83 ea 01 75 90 00 } //01 00 
		$a_01_1 = {52 65 67 4f 70 65 6e 4b 65 79 54 72 61 6e 73 61 63 74 65 64 57 } //01 00 
		$a_01_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00 
		$a_01_3 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //01 00 
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00 
		$a_01_5 = {50 6f 73 74 4d 65 73 73 61 67 65 57 } //01 00 
		$a_01_6 = {47 65 74 4b 65 79 53 74 61 74 65 } //01 00 
		$a_01_7 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00 
	condition:
		any of ($a_*)
 
}