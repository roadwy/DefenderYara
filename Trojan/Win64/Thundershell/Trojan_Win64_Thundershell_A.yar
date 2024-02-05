
rule Trojan_Win64_Thundershell_A{
	meta:
		description = "Trojan:Win64/Thundershell.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 ea 01 83 fa 01 77 05 e8 90 01 04 b8 01 00 00 00 48 83 c4 28 c3 90 00 } //0a 00 
		$a_03_1 = {41 b8 01 10 00 00 4c 8d 4c 24 20 4c 89 c9 e8 90 01 04 49 89 c1 8b 05 90 01 04 85 c0 74 08 90 00 } //0a 00 
		$a_01_2 = {44 6c 6c 4d 61 69 6e 00 45 78 65 63 00 } //00 00 
		$a_00_3 = {5d 04 00 00 2d a9 03 80 5c 22 00 00 2e a9 03 80 00 00 01 00 04 00 0c 00 89 21 53 63 68 6f } //70 65 
	condition:
		any of ($a_*)
 
}