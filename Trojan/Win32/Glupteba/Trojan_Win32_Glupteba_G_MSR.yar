
rule Trojan_Win32_Glupteba_G_MSR{
	meta:
		description = "Trojan:Win32/Glupteba.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c2 89 44 24 28 89 2d c0 a4 7e 00 8b 44 24 28 29 44 24 14 81 3d e4 14 14 05 d5 01 00 00 75 27 } //01 00 
		$a_01_1 = {c1 ea 05 89 54 24 18 c7 05 88 33 0d 05 2e ce 50 91 8b 44 24 3c 01 44 24 18 81 3d e4 14 14 05 12 09 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_G_MSR_2{
	meta:
		description = "Trojan:Win32/Glupteba.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 94 01 3b 2d 0b 00 8b 0d 90 02 04 00 88 14 01 c3 90 0a 16 8b 0d 90 02 04 00 90 00 } //03 00 
		$a_03_1 = {40 00 8b 0d 90 01 02 40 00 8b 15 90 01 02 40 00 a3 90 01 03 00 66 a1 90 01 02 40 00 89 0d 90 01 03 00 8a 0d 90 01 02 40 00 89 15 90 01 03 00 66 a3 90 01 03 00 88 0d 90 01 03 00 c6 05 90 01 03 00 69 c6 05 90 01 03 00 72 90 00 } //03 00 
		$a_03_2 = {40 00 8b 0d 90 01 02 40 00 8b 15 90 01 02 40 00 a3 90 01 03 00 66 a1 90 01 02 40 00 89 0d 90 01 03 00 8a 0d 90 01 02 40 00 89 15 90 01 03 00 66 a3 90 01 03 00 88 0d 90 01 03 00 66 c7 05 90 01 03 00 69 72 90 00 } //01 00 
		$a_01_3 = {56 65 62 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VebtualProtect
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}