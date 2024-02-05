
rule TrojanDropper_Win32_Agent_RH{
	meta:
		description = "TrojanDropper:Win32/Agent.RH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {bf 43 3a 5c 52 be 65 63 79 63 } //01 00 
		$a_00_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 2e 65 78 65 } //01 00 
		$a_00_2 = {63 6d 64 20 2f 63 20 63 6f 70 79 20 25 73 20 25 73 } //01 00 
		$a_00_3 = {25 73 25 64 63 6e 6e 61 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}