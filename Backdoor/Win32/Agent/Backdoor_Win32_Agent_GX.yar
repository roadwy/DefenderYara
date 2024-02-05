
rule Backdoor_Win32_Agent_GX{
	meta:
		description = "Backdoor:Win32/Agent.GX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 69 70 65 5c 5f 36 39 } //01 00 
		$a_01_1 = {5c 74 65 6d 70 2e 74 65 6d 70 } //01 00 
		$a_03_2 = {41 8a 94 38 90 01 02 00 10 8a 99 90 01 02 00 10 32 d3 88 97 90 01 02 00 10 75 06 88 9f 90 01 02 00 10 47 3b 7d fc 7c ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}