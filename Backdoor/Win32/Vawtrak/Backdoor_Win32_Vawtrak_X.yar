
rule Backdoor_Win32_Vawtrak_X{
	meta:
		description = "Backdoor:Win32/Vawtrak.X,SIGNATURE_TYPE_PEHSTR,67 00 67 00 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 25 73 2e 25 73 2f 66 61 76 69 63 6f 6e 2e 69 63 6f } //01 00 
		$a_01_1 = {23 64 6f 6d 61 69 6e } //01 00 
		$a_01_2 = {23 62 6f 74 69 64 } //01 00 
		$a_01_3 = {23 63 66 67 6c 6f 61 64 } //01 00 
		$a_01_4 = {23 64 62 67 6d 73 67 } //01 00 
		$a_01_5 = {23 64 65 6c 66 69 6c 65 } //01 00 
		$a_01_6 = {73 6f 6c 5f 6c 6f 77 2f } //01 00 
		$a_01_7 = {66 72 61 6d 65 77 6f 72 6b 5f 6b 65 79 25 } //00 00 
		$a_01_8 = {00 61 } //8f 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Vawtrak_X_2{
	meta:
		description = "Backdoor:Win32/Vawtrak.X,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 64 3d 25 30 2e 38 58 25 30 2e 38 58 25 30 2e 38 58 25 30 2e 34 58 25 30 2e 34 58 25 30 2e 34 58 26 69 76 3d 25 30 2e 38 58 26 61 76 3d 25 30 2e 38 58 26 75 70 74 69 6d 65 3d 25 75 } //01 00 
		$a_01_1 = {26 69 6e 66 6f 3d 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 34 58 25 30 2e 32 58 25 30 2e 34 58 26 70 72 6f 78 79 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Vawtrak_X_3{
	meta:
		description = "Backdoor:Win32/Vawtrak.X,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 } //01 00 
		$a_01_1 = {7e 00 25 00 30 00 2e 00 38 00 78 00 2e 00 65 00 78 00 65 00 } //00 00 
		$a_01_2 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}