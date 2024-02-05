
rule Trojan_Win64_IcedID_MH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6c 6d 71 32 35 37 71 74 38 2e 64 6c 6c } //01 00 
		$a_01_1 = {42 79 55 65 64 37 34 31 62 } //01 00 
		$a_01_2 = {44 54 65 54 36 30 33 72 4b 52 } //01 00 
		$a_01_3 = {4e 66 75 34 34 65 } //01 00 
		$a_01_4 = {54 49 4a 6c 4f 36 31 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MH_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {88 08 48 8b 04 24 66 3b ed 74 90 01 01 48 8b 44 24 08 48 ff c0 3a d2 74 90 01 01 48 ff c8 48 89 44 24 30 eb 90 00 } //05 00 
		$a_01_1 = {75 69 73 62 61 64 79 75 67 61 75 73 62 64 6a 61 73 79 75 64 6a 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MH_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_1 = {51 55 71 73 32 73 7a 6b 48 68 6e } //01 00 
		$a_01_2 = {4b 4b 52 41 55 2e 64 6c 6c } //01 00 
		$a_01_3 = {72 64 52 54 61 44 49 43 } //01 00 
		$a_01_4 = {73 67 4e 6b 41 59 41 76 52 4c 39 } //01 00 
		$a_01_5 = {78 57 57 35 51 4d } //00 00 
	condition:
		any of ($a_*)
 
}