
rule PWS_Win64_Sinowal_gen_A{
	meta:
		description = "PWS:Win64/Sinowal.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 69 48 8b 44 24 20 0f be 00 83 c8 60 89 44 24 08 48 c7 04 24 01 00 00 00 eb 0c 48 8b 04 24 48 83 c0 01 } //01 00 
		$a_03_1 = {49 63 46 3c 42 81 3c 30 50 45 00 00 0f 85 90 01 04 66 42 81 7c 30 18 0b 02 0f 85 90 00 } //01 00 
		$a_01_2 = {49 8b 4d 20 49 8b 45 18 4c 89 1c c8 49 83 45 20 01 41 81 3c bc 18 05 e5 54 } //01 00 
		$a_01_3 = {26 69 74 61 67 3d 6f 64 79 26 71 3d 25 73 25 25 32 43 25 } //00 00 
	condition:
		any of ($a_*)
 
}