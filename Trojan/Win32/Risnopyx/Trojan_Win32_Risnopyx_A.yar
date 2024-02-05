
rule Trojan_Win32_Risnopyx_A{
	meta:
		description = "Trojan:Win32/Risnopyx.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 4c 6f 63 6b 65 72 20 4c 6f 63 6b 20 4d 6f 64 75 6c 65 } //01 00 
		$a_03_1 = {70 75 62 6b 65 79 2e 62 69 6e 00 90 02 03 2e 72 61 6e 73 00 90 00 } //01 00 
		$a_03_2 = {50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 90 02 08 45 4e 43 52 59 50 54 45 44 00 90 00 } //01 00 
		$a_03_3 = {8b 44 24 08 8b 4c 24 04 6a 00 6a 00 6a 00 6a 00 6a 00 50 51 68 90 01 04 68 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}