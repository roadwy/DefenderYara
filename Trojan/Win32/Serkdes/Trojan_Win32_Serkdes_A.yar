
rule Trojan_Win32_Serkdes_A{
	meta:
		description = "Trojan:Win32/Serkdes.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 79 70 77 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //01 00 
		$a_01_1 = {30 28 65 6e 63 72 79 70 74 29 20 6f 72 20 31 28 64 65 63 72 79 70 74 29 } //01 00 
		$a_00_2 = {8b 9c 96 00 03 00 00 8a 51 ff 0b fb 49 8b d8 83 e2 3f 83 e3 3f 33 d3 c1 f8 04 8b 9c 96 00 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}