
rule Trojan_Win32_SmkLdr_A_MTB{
	meta:
		description = "Trojan:Win32/SmkLdr.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 16 8b 46 68 83 e0 70 85 c0 75 0c 8b 46 18 8b 40 10 85 c0 } //01 00 
		$a_01_1 = {80 00 98 40 38 18 75 f8 } //01 00 
		$a_03_2 = {66 01 08 8d 40 02 66 39 18 75 f0 90 09 05 00 b9 90 01 02 00 00 90 00 } //01 00 
		$a_00_3 = {5a eb 0c 03 ca 68 00 80 00 00 6a 00 57 ff 11 8b c6 5a 5e 5f 59 5b 5d ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}