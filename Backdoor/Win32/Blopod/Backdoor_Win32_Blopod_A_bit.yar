
rule Backdoor_Win32_Blopod_A_bit{
	meta:
		description = "Backdoor:Win32/Blopod.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {26 67 72 6f 75 70 3d 00 72 65 73 6f 75 72 63 65 2e 70 68 70 3f 68 77 69 64 3d } //01 00  朦潲灵=敲潳牵散瀮灨栿楷㵤
		$a_01_1 = {48 54 54 50 2d 66 6c 6f 6f 64 } //01 00  HTTP-flood
		$a_01_2 = {54 43 50 2d 66 6c 6f 6f 64 } //01 00  TCP-flood
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 65 78 65 63 75 74 65 } //01 00  Download and execute
		$a_01_4 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 } //01 00  schtasks /create /tn 
		$a_03_5 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 90 02 20 2e 6c 6e 6b 90 00 } //01 00 
		$a_03_6 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 90 02 20 2e 65 78 65 90 00 } //01 00 
		$a_01_7 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 } //00 00  taskkill /f /im 
	condition:
		any of ($a_*)
 
}