
rule Trojan_Win32_Tedy_NBL_MTB{
	meta:
		description = "Trojan:Win32/Tedy.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 40 44 52 4c 00 00 8b 4a 6c 03 4a 5c a1 90 01 04 81 f1 b8 14 0d 00 89 48 54 8b 8a e0 00 00 00 2b 8a 34 01 00 00 a1 90 01 04 81 f1 f1 0e 1e 00 81 f6 a3 46 00 00 89 88 2c 01 00 00 8b c6 5e 5b c3 90 00 } //01 00 
		$a_03_1 = {8b 8e 08 01 00 00 b8 c0 77 00 00 33 8e 90 01 04 8b 15 90 01 04 2b c1 01 42 28 81 f7 8c 0f 00 00 8b c7 c7 86 08 01 00 00 90 01 04 5f 5e 5d 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}