
rule Trojan_Win32_Emotet_DQ{
	meta:
		description = "Trojan:Win32/Emotet.DQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 71 00 31 00 65 00 2b 00 3e 00 57 00 4a 00 26 00 6e 00 3d 00 } //01 00 
		$a_01_1 = {6b 00 5a 00 4d 00 62 00 4b 00 77 00 2b 00 6f 00 23 00 37 00 79 00 } //01 00 
		$a_01_2 = {67 77 65 72 67 6b 6a 77 65 6f 69 6a 67 23 40 34 68 6a 6e 6c 77 72 6b 77 2e 50 44 42 } //00 00 
	condition:
		any of ($a_*)
 
}