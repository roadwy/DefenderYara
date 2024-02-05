
rule Trojan_Win64_Ampskerk_A_dha{
	meta:
		description = "Trojan:Win64/Ampskerk.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 3a 26 75 1b 66 83 38 4b 75 15 66 83 78 0e 73 75 0e 66 83 78 1e 4b } //01 00 
		$a_01_1 = {41 bb 48 b8 00 00 66 44 89 1f 4c 89 77 02 c6 47 0a c3 } //01 00 
		$a_01_2 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 00 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}