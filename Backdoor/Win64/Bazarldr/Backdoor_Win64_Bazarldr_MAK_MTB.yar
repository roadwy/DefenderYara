
rule Backdoor_Win64_Bazarldr_MAK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be c0 48 ff c1 03 d0 69 d2 90 02 02 00 00 8b c2 c1 f8 90 02 01 33 d0 8a 01 84 c0 75 90 00 } //01 00 
		$a_03_1 = {8d 0c d2 8b c1 c1 f8 90 02 01 33 c1 69 c0 90 02 02 00 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win64_Bazarldr_MAK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a c1 02 85 90 02 04 30 84 0d 90 02 04 48 03 cf 48 83 f9 90 02 01 72 90 00 } //01 00 
		$a_03_1 = {02 c8 30 4c 04 90 02 01 49 03 c6 48 83 f8 90 02 01 73 06 8a 4c 24 90 02 01 eb 90 00 } //01 00 
		$a_03_2 = {8a 44 24 20 02 c1 30 44 0c 90 02 01 49 03 ce 48 83 f9 90 02 01 72 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}