
rule Trojan_Win32_Injector_YL_bit{
	meta:
		description = "Trojan:Win32/Injector.YL!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 73 05 8d 6c 24 10 2b ee 8a 06 84 c0 74 11 32 c2 2a c1 fe c8 88 04 2e 41 46 3b cf 72 eb eb 03 } //02 00 
		$a_03_1 = {8a 49 02 8a 15 90 01 04 8b f8 33 c0 55 02 ca 30 0c 30 8b 0d 90 01 04 8a 49 02 0f b6 e9 40 81 c5 90 01 04 3b c5 76 e4 90 00 } //02 00 
		$a_03_2 = {8b ff 8a 81 90 01 04 84 c0 74 11 32 c2 2a c1 fe c8 88 44 0c 08 41 3b ce 72 e7 eb 07 c6 05 90 01 04 00 90 00 } //01 00 
		$a_03_3 = {83 78 14 00 75 3b 83 78 18 00 75 35 6a 00 6a 00 6a 11 6a fe ff 15 90 01 02 40 00 8b 0e 89 0d 90 01 04 e8 90 00 } //01 00 
		$a_01_4 = {46 55 43 4b 20 4f 46 46 21 21 21 } //00 00 
		$a_00_5 = {5d 04 00 00 } //aa 74 
	condition:
		any of ($a_*)
 
}