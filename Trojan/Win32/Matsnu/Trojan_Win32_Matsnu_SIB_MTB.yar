
rule Trojan_Win32_Matsnu_SIB_MTB{
	meta:
		description = "Trojan:Win32/Matsnu.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 40 00 00 00 90 02 10 50 90 02 05 b9 00 30 00 00 90 02 05 51 ff 75 14 33 c0 90 02 2a 50 90 02 10 ff 15 90 01 04 90 02 05 8b f8 89 3d 90 00 } //01 00 
		$a_03_1 = {8b c7 88 08 90 02 05 83 c7 01 90 02 10 89 35 90 01 04 90 02 08 bb f1 28 41 00 90 02 10 29 1d 90 1b 02 90 18 90 02 10 8a 0e 90 02 10 46 90 02 10 80 c1 90 01 01 90 02 0a c0 c9 90 01 01 90 02 10 fe c9 90 02 0a 32 0d 90 01 04 90 02 05 c0 c1 90 01 01 90 02 0a fe c1 90 02 10 c0 c9 90 01 01 90 02 0a c0 c9 90 01 01 90 02 05 c0 c1 90 01 01 90 02 10 c0 c1 90 01 01 90 02 0a 80 c1 90 01 01 90 02 10 fe c9 90 02 05 fe c9 90 02 10 fe c1 90 02 0a fe c1 90 02 10 fe c9 90 02 10 c0 c9 90 01 01 90 02 10 8b c7 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}