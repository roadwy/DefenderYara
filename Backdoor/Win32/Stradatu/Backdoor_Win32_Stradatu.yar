
rule Backdoor_Win32_Stradatu{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 46 4e 3d 25 73 26 4c 46 4c 3d 25 6c 64 26 52 46 4e 3d 25 73 } //01 00 
		$a_01_1 = {66 72 69 65 6e 64 20 69 73 20 55 6e 61 76 61 69 6c 61 62 6c 65 21 } //01 00 
		$a_01_2 = {3a 5c 70 6a 74 73 32 30 30 38 5c 53 75 6e 54 61 6c 6b 5c 52 65 6c 65 61 73 65 5c 53 54 61 6c 6b 5f 53 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_2{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 71 66 69 6c 65 20 6e 6f 74 20 65 78 69 73 74 21 } //01 00 
		$a_01_1 = {64 20 66 69 6c 65 20 66 61 69 6c 75 72 65 21 } //01 00 
		$a_01_2 = {59 32 31 6b 4c 6d 56 34 5a 51 3d 3d } //01 00 
		$a_01_3 = {52 55 68 65 59 6f 64 74 61 58 79 75 64 54 79 34 61 33 49 35 4e 6a 56 78 4e 6b 5a 78 50 52 21 21 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_3{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 2e 33 2e 36 2e 31 2e 35 2e 35 2e 37 2e 33 2e 32 } //01 00 
		$a_01_1 = {34 2e 31 2e 33 31 31 2e 31 30 2e 33 2e 33 } //02 00 
		$a_01_2 = {52 45 56 45 52 53 45 53 48 45 4c 4c } //02 00 
		$a_01_3 = {55 4e 4b 4e 4f 57 20 43 4c 49 45 4e 54 20 54 59 50 45 } //02 00 
		$a_01_4 = {55 4e 4b 4e 4f 57 20 48 4f 53 54 20 54 59 50 45 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_4{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 78 6a 6d 70 73 76 61 6c 7a 79 64 67 } //01 00 
		$a_01_1 = {2a 26 75 73 65 72 69 64 3d 2a 2a 2a 2a 26 6f 74 68 65 72 3d } //01 00 
		$a_01_2 = {70 74 5f 4c 58 43 5f 33 } //01 00 
		$a_01_3 = {74 65 20 43 6f 6d 6d 61 6e 64 20 53 6f 63 6b 65 74 20 42 75 69 6c 64 20 4f 4b 21 } //01 00 
		$a_01_4 = {61 74 20 22 49 50 20 50 4f 52 54 22 21 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_5{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 20 50 61 74 68 20 69 73 20 6e 75 6c 6c 21 } //01 00 
		$a_01_1 = {3c 54 49 54 4c 45 3e 44 69 73 70 6c 61 79 20 49 6e 66 6f 20 66 6f 72 20 74 68 69 73 20 53 49 54 45 21 3c 2f 54 49 54 4c 45 3e } //01 00 
		$a_01_2 = {63 6f 6e 74 65 6e 74 3d 71 75 69 74 } //01 00 
		$a_01_3 = {25 61 2c 20 25 64 20 25 62 20 25 59 20 25 48 3a 25 4d 3a 25 53 20 47 4d 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_6{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 20 71 75 69 74 21 5b 61 6c 6c 20 73 6c 65 65 70 20 6e 6e 6e 20 74 69 6d 65 5d } //01 00 
		$a_01_1 = {3c 4e 55 4c 4c 3e 20 50 61 73 73 77 6f 72 64 3c 4e 55 4c 4c 3e 20 44 6f 6d 61 69 6e 3c 4e 55 4c 4c 3e } //01 00 
		$a_01_2 = {2a 2a 2a 20 4a 4d 53 2d 48 54 20 2a 2a 2a } //01 00 
		$a_01_3 = {6c 20 69 6e 20 61 6e 6f 74 68 65 72 20 73 68 65 6c 6c 21 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_7{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 61 62 63 20 2f 61 64 64 } //01 00 
		$a_01_1 = {74 20 75 73 65 72 20 61 62 63 20 61 62 63 20 2f 61 64 64 } //01 00 
		$a_01_2 = {52 65 71 50 61 74 68 20 69 73 20 6e 75 6c 6c 21 } //01 00 
		$a_01_3 = {41 52 45 20 59 4f 55 20 53 55 52 45 20 43 4c 4f 53 45 20 43 4c 49 45 4e 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Stradatu_8{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6f 72 20 71 75 69 74 21 5b 61 6c 6c 20 73 6c 65 65 70 20 6e 6e 6e 20 74 69 6d 65 5d } //01 00 
		$a_01_1 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 4e 65 77 20 63 6c 69 65 6e 74 20 63 6f 6d 69 6e 67 20 21 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a } //01 00 
		$a_01_2 = {42 61 64 20 43 6c 69 65 6e 74 2c 20 70 6c 65 61 73 65 20 72 65 6d 6f 76 65 20 69 74 21 } //01 00 
		$a_01_3 = {25 73 20 67 6f 65 73 20 74 6f 20 62 65 64 21 20 57 69 73 68 20 68 69 6d 20 61 20 67 6f 6f 64 20 73 6c 65 65 70 21 } //00 00 
	condition:
		any of ($a_*)
 
}