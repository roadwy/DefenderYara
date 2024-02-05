
rule TrojanClicker_Win32_Agent_AA{
	meta:
		description = "TrojanClicker:Win32/Agent.AA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 70 63 66 67 2e 6a 37 79 2e 6e 65 74 2f 75 70 63 66 67 2f 4e 65 77 55 70 63 66 67 2e 61 73 70 3f 49 44 3d 25 64 } //02 00 
		$a_01_1 = {43 68 65 63 6b 49 45 41 64 76 54 68 64 } //01 00 
		$a_01_2 = {44 6f 77 6e 4c 6f 61 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}