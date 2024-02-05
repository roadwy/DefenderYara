
rule Trojan_Win64_Sirefef_D{
	meta:
		description = "Trojan:Win64/Sirefef.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 8b 9c 24 b8 00 00 00 44 33 9c 24 bc 00 00 00 } //01 00 
		$a_03_1 = {41 b0 3b 48 8b d0 2b c8 e8 90 01 04 48 85 c0 74 24 48 8b d0 48 2b d3 48 83 fa 40 90 00 } //02 00 
		$a_01_2 = {68 69 74 3f 74 35 32 2e 36 3b 72 68 74 74 70 3a 2f 2f 25 75 3b 73 25 75 2a 25 75 2a 25 75 3b 75 2f 25 75 3b 30 2e 25 75 25 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Sirefef_D_2{
	meta:
		description = "Trojan:Win64/Sirefef.D,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 8b 9c 24 b8 00 00 00 44 33 9c 24 bc 00 00 00 } //01 00 
		$a_03_1 = {41 b0 3b 48 8b d0 2b c8 e8 90 01 04 48 85 c0 74 24 48 8b d0 48 2b d3 48 83 fa 40 90 00 } //02 00 
		$a_01_2 = {68 69 74 3f 74 35 32 2e 36 3b 72 68 74 74 70 3a 2f 2f 25 75 3b 73 25 75 2a 25 75 2a 25 75 3b 75 2f 25 75 3b 30 2e 25 75 25 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}