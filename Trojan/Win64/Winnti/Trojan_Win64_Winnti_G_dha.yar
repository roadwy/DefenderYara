
rule Trojan_Win64_Winnti_G_dha{
	meta:
		description = "Trojan:Win64/Winnti.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 50 61 73 73 77 6f 72 64 } //01 00 
		$a_01_1 = {77 6f 72 6b 64 6c 6c 36 34 2e 64 6c 6c } //01 00 
		$a_01_2 = {77 6f 72 6b 5f 73 74 61 72 74 } //01 00 
		$a_01_3 = {77 6f 72 6b 5f 65 6e 64 } //01 00 
		$a_01_4 = {25 73 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //01 00 
		$a_01_5 = {2f 6c 6f 6f 6b 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 73 
	condition:
		any of ($a_*)
 
}