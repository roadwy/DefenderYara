
rule Trojan_Win32_Famudin_A{
	meta:
		description = "Trojan:Win32/Famudin.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 61 8b 44 24 28 8b 35 90 01 04 50 ff d6 8b 44 24 14 85 c0 75 05 90 00 } //01 00 
		$a_01_1 = {4d 41 46 46 62 6f 64 79 2e 65 78 65 00 } //01 00 
		$a_01_2 = {41 75 64 69 6f 4e 20 66 75 6e 63 74 69 6f 6e 20 30 78 25 78 } //00 00 
	condition:
		any of ($a_*)
 
}