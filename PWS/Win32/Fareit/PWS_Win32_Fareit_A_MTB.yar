
rule PWS_Win32_Fareit_A_MTB{
	meta:
		description = "PWS:Win32/Fareit.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {ff 34 0e 81 34 24 0f ba b9 7a 8f 04 08 c3 } //0a 00 
		$a_02_1 = {6a 40 ff d0 e8 90 01 04 5e 81 c6 90 01 04 68 90 01 04 59 83 e9 04 e8 90 01 04 83 e9 03 e0 f6 e8 90 01 04 ff e0 90 00 } //00 00 
		$a_00_2 = {78 e7 01 00 02 00 02 00 0d 00 } //00 01 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fareit_A_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0d 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_03_1 = {31 34 24 81 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8b 0c 24 90 02 ff 89 0c 18 90 00 } //01 00 
		$a_03_2 = {31 34 24 85 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8b 0c 24 90 02 ff 89 0c 18 90 00 } //01 00 
		$a_03_3 = {31 34 24 66 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8b 0c 24 90 02 ff 89 0c 18 90 00 } //01 00 
		$a_03_4 = {31 34 24 66 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_5 = {31 34 24 85 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_6 = {31 34 24 81 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_7 = {31 34 24 eb 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_8 = {31 34 24 66 90 0a ff 00 ff 31 90 02 ff 31 34 24 90 02 ff 8f 04 10 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_9 = {8f 04 10 66 90 0a ff 00 ff 31 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_10 = {8f 04 10 81 90 0a ff 00 ff 31 90 02 ff 31 34 24 90 02 ff 8f 04 10 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_11 = {8f 04 18 81 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8f 04 10 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //01 00 
		$a_03_12 = {8f 04 18 66 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8f 04 18 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fareit_A_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 02 90 90 90 34 dd 88 45 fb 90 90 90 90 90 8b 4d fc 8a 45 fb 88 01 90 8b 45 f4 40 89 45 f4 90 90 90 ff 45 f0 42 81 7d } //01 00 
		$a_01_1 = {4d 71 62 69 32 57 46 65 79 66 31 } //01 00  Mqbi2WFeyf1
		$a_01_2 = {50 6f 6e 5a 50 74 41 4a 30 6a 48 45 } //00 00  PonZPtAJ0jHE
	condition:
		any of ($a_*)
 
}