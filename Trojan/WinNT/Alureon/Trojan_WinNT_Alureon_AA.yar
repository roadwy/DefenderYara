
rule Trojan_WinNT_Alureon_AA{
	meta:
		description = "Trojan:WinNT/Alureon.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb 42 4b 46 53 53 c1 e0 09 50 6a 00 ff 15 } //01 00 
		$a_01_1 = {89 48 08 89 48 58 89 48 34 e8 } //01 00 
		$a_01_2 = {5b 69 6e 6a 65 63 74 73 5f 65 6e 64 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Alureon_AA_2{
	meta:
		description = "Trojan:WinNT/Alureon.AA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 45 f4 50 6a 00 6a 01 53 ff 15 90 01 04 85 c0 74 5c 8b 50 20 8b 70 1c 8b 78 24 8b 40 18 90 00 } //01 00 
		$a_00_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 73 00 74 00 61 00 72 00 74 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 } //01 00 
		$a_00_2 = {25 00 73 00 5c 00 70 00 68 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}