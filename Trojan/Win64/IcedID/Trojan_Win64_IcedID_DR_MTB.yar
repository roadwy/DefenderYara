
rule Trojan_Win64_IcedID_DR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8d 50 ff 0f af d0 89 d0 83 f0 fe 85 d0 0f 94 c2 0f 94 44 24 06 41 b9 ab d8 35 48 41 b8 a0 2a 8a 08 b8 a0 2a 8a 08 41 0f 44 c1 83 f9 0a 0f 9c 44 24 } //03 00 
		$a_81_1 = {53 73 78 6c 79 6b 73 6d 55 70 65 64 70 66 6a 74 62 4d 6d 78 74 79 6b 6a 63 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DR_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {71 70 4b 4f 70 2e 64 6c 6c } //01 00 
		$a_01_1 = {43 61 6f 56 56 54 48 36 4a 4c } //01 00 
		$a_01_2 = {44 47 46 49 75 30 66 6c 6a 76 } //01 00 
		$a_01_3 = {48 42 70 79 73 52 66 4e 59 5a } //01 00 
		$a_01_4 = {48 4c 76 48 53 54 55 31 53 4c } //0a 00 
		$a_01_5 = {4f 6b 41 44 78 50 4a 68 2e 64 6c 6c } //01 00 
		$a_01_6 = {49 55 56 34 49 56 51 79 6e 6c 37 } //01 00 
		$a_01_7 = {61 67 6a 68 73 61 68 6a 61 73 6b 73 64 } //01 00 
		$a_01_8 = {71 43 7a 67 64 39 31 68 39 } //01 00 
		$a_01_9 = {75 41 66 53 62 53 6a 71 50 64 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DR_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d 78 8b c7 41 0f af c8 2b c1 44 0f af c0 8b 4d 78 8b 85 80 00 00 00 03 c8 b8 56 55 55 55 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 } //00 00 
	condition:
		any of ($a_*)
 
}