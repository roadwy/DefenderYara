
rule Trojan_Win32_Zlob_G{
	meta:
		description = "Trojan:Win32/Zlob.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {a5 a5 a4 8d bd fc fe ff ff 4f 8a 47 01 47 3a c3 75 f8 be 90 01 03 10 53 a5 53 53 a5 90 00 } //01 00 
		$a_00_1 = {7b 42 38 33 30 31 41 46 37 2d 44 30 30 45 2d 34 45 41 34 2d 38 37 43 31 2d 35 46 46 34 36 34 34 46 42 42 41 31 7d } //01 00 
		$a_00_2 = {68 6f 6d 65 73 65 63 75 72 65 70 61 67 65 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zlob_G_2{
	meta:
		description = "Trojan:Win32/Zlob.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {a5 a5 a4 8d bd fc fe ff ff 4f 8a 47 01 47 84 c0 75 f8 be 90 01 03 10 a5 6a 00 6a 00 a5 90 00 } //01 00 
		$a_00_1 = {7b 42 38 33 30 31 41 46 37 2d 44 30 30 45 2d 34 45 41 34 2d 38 37 43 31 2d 35 46 46 34 36 34 34 46 42 42 41 31 7d } //01 00 
		$a_00_2 = {68 6f 6d 65 73 65 63 75 72 65 70 61 67 65 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}