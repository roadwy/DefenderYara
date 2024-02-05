
rule Trojan_Win32_Remcos_BB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 a1 90 01 04 8b 08 8b 15 90 01 04 8b 04 91 2d 90 01 04 89 45 fc 8b 0d 90 01 04 83 c1 01 89 0d 90 01 04 8b 45 fc 8b e5 5d c3 90 00 } //01 00 
		$a_03_1 = {c6 44 24 2a 33 66 c7 44 24 90 01 01 6b 65 c6 44 24 90 01 01 00 c6 44 24 90 01 01 56 c6 44 24 90 01 01 74 c6 44 24 90 01 01 6c 90 00 } //01 00 
		$a_03_2 = {2b d0 33 05 90 01 04 c6 44 24 90 01 01 6e c6 44 24 90 01 01 32 c6 44 24 90 01 01 6f c6 44 24 90 01 01 75 3b c2 7f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}