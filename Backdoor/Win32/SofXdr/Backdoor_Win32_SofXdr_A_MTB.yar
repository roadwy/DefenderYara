
rule Backdoor_Win32_SofXdr_A_MTB{
	meta:
		description = "Backdoor:Win32/SofXdr.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 73 75 6c 74 73 2f 3f 61 67 73 3d 5f 5f 5f 5f 5f 5f 5f 5f 5f 26 61 67 73 3d 5f 5f 5f 5f 5f 5f 5f 5f 5f 26 } //01 00  results/?ags=_________&ags=_________&
		$a_01_1 = {43 00 3a 00 5c 00 49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //01 00  C:\INTERNAL\REMOTE.EXE
		$a_01_2 = {59 62 70 72 53 4e 53 49 73 48 4d 4f 74 4c 6b 55 77 55 5a 70 57 6c 64 6c 4a 4b 66 54 72 5a 58 67 48 4e } //01 00  YbprSNSIsHMOtLkUwUZpWldlJKfTrZXgHN
		$a_01_3 = {69 00 73 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 } //01 00  is running
		$a_01_4 = {69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 } //00 00  is not running
		$a_00_5 = {5d 04 00 00 } //52 c3 
	condition:
		any of ($a_*)
 
}