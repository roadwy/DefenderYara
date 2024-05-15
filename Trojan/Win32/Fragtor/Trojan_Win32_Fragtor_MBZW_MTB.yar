
rule Trojan_Win32_Fragtor_MBZW_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 29 05 90 01 04 30 5c 24 90 01 01 8d 04 2a 89 44 24 90 01 01 8b c7 2b c2 0f af 44 24 90 00 } //01 00 
		$a_01_1 = {83 3d dc 23 42 00 00 8a 91 f8 53 41 00 75 08 a1 f4 27 42 00 88 14 01 41 3b cf } //00 00 
	condition:
		any of ($a_*)
 
}