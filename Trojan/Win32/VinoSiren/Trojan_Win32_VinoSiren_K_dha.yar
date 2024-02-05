
rule Trojan_Win32_VinoSiren_K_dha{
	meta:
		description = "Trojan:Win32/VinoSiren.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 49 34 59 6f 75 40 31 32 21 21 21 } //01 00 
		$a_01_1 = {5c 44 4d 25 64 25 30 32 64 25 30 32 64 2e 6e 6c 73 } //01 00 
		$a_01_2 = {23 23 23 20 7b 2f 43 4c 49 50 42 4f 41 52 44 7d 20 23 23 23 } //01 00 
		$a_01_3 = {4d 79 48 6f 6f 6b 20 53 65 73 73 69 6f 6e } //01 00 
		$a_01_4 = {4b 42 39 38 37 33 32 34 2e 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}