
rule TrojanDropper_Win32_Koutodoor_B{
	meta:
		description = "TrojanDropper:Win32/Koutodoor.B,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 72 6b 64 6f 6f 72 } //0a 00  \\.\Global\rkdoor
		$a_00_1 = {25 73 5c 25 73 20 25 73 5c 25 73 2e 64 6c 6c 2c 25 73 } //05 00  %s\%s %s\%s.dll,%s
		$a_02_2 = {53 74 61 72 74 20 50 61 67 65 90 02 04 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 90 02 04 3f 74 6e 3d 90 00 } //01 00 
		$a_00_3 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //01 00  system32\drivers\%s.sys
		$a_00_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //00 00  SYSTEM\CurrentControlSet\Services\%s
	condition:
		any of ($a_*)
 
}