
rule Backdoor_Win32_Zegost_DD{
	meta:
		description = "Backdoor:Win32/Zegost.DD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_00_0 = {4b 42 44 4c 6f 67 65 72 } //01 00  KBDLoger
		$a_01_1 = {5b 45 58 45 43 55 54 45 5f 6b 65 79 5d } //01 00  [EXECUTE_key]
		$a_00_2 = {47 6c 6f 62 61 6c 5c 61 69 72 6b 79 } //01 00  Global\airky
		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 48 69 67 68 53 79 73 74 65 6d } //00 00  rundll32.exe "%s",HighSystem
		$a_00_4 = {78 86 00 } //00 05 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zegost_DD_2{
	meta:
		description = "Backdoor:Win32/Zegost.DD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74 } //02 00 
		$a_03_1 = {8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b 90 01 01 7c 90 00 } //02 00 
		$a_03_2 = {4b c6 44 24 90 01 01 52 c6 44 24 90 01 01 4e c6 44 24 90 01 01 4c c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e 90 00 } //01 00 
		$a_01_3 = {55 c6 00 4d c6 40 01 5a 66 81 38 4d 5a } //00 00 
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}