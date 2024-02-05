
rule Backdoor_Win64_Bazarloader_SSA{
	meta:
		description = "Backdoor:Win64/Bazarloader.SSA,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {41 55 41 54 57 56 53 48 83 ec 50 48 b8 90 02 08 8b 9c 24 a8 00 00 00 8b b4 24 b0 00 00 00 48 8b bc 24 b8 00 00 00 48 89 44 24 40 45 89 c5 45 89 c8 49 89 d4 90 00 } //05 00 
		$a_02_1 = {c7 44 24 3c 90 02 04 4c 8b 8c 24 a0 00 00 00 c7 44 24 48 90 02 04 c6 44 24 4c 00 48 89 44 24 34 31 c0 90 00 } //05 00 
		$a_00_2 = {4c 8b 4c 24 28 44 89 ea 4c 89 e1 44 8b 44 24 24 48 89 bc 24 b0 00 00 00 89 b4 24 a8 00 00 00 89 9c 24 a0 00 00 00 48 83 c4 50 5b 5e 5f 41 5c 41 5d 48 ff e0 } //00 00 
		$a_00_3 = {5d 04 00 00 b4 a2 04 80 5c 37 } //00 00 
	condition:
		any of ($a_*)
 
}