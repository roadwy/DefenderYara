
rule Backdoor_Win32_Agent_OY{
	meta:
		description = "Backdoor:Win32/Agent.OY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b0 53 b1 45 88 44 24 90 01 01 88 44 24 90 01 01 b0 52 88 4c 24 90 01 01 88 44 24 90 01 01 88 44 24 90 00 } //01 00 
		$a_03_1 = {50 c6 44 24 90 01 01 55 c6 44 24 90 01 01 52 c6 44 24 90 01 01 4c c6 44 24 90 01 01 44 88 4c 24 90 01 01 c6 44 24 90 01 01 77 90 00 } //01 00 
		$a_00_2 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00  GET %s HTTP/1.1
		$a_03_3 = {6a 06 8d 85 90 01 02 ff ff 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}