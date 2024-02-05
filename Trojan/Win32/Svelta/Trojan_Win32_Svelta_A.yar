
rule Trojan_Win32_Svelta_A{
	meta:
		description = "Trojan:Win32/Svelta.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b2 be b1 ad b0 de 88 54 90 01 01 0e 88 4c 24 0f 88 44 24 10 88 4c 24 16 90 00 } //01 00 
		$a_01_1 = {8b 46 04 6a 00 89 4e 09 8b 0e 51 55 53 57 89 56 10 89 46 15 } //01 00 
		$a_01_2 = {66 69 72 65 66 6f 78 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}