
rule Trojan_Win32_Donut_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Donut.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f3 2b fb 8b e9 8a 04 37 30 06 46 83 ed 01 } //01 00 
		$a_01_1 = {03 cf 03 c6 c1 c7 05 33 f9 c1 c6 08 33 f0 c1 c1 10 03 c7 03 ce c1 c7 07 c1 c6 0d 33 f8 33 f1 c1 c0 10 83 6c 24 30 01 75 d7 8b 6c 24 28 89 4c 24 14 33 c9 89 74 24 20 89 7c 24 18 89 44 24 1c 8b 44 8d 00 31 44 8c 14 41 83 f9 04 } //00 00 
	condition:
		any of ($a_*)
 
}