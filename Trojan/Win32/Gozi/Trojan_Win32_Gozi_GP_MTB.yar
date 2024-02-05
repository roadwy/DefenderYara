
rule Trojan_Win32_Gozi_GP_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 f4 8b 0d 90 01 04 83 c0 90 01 01 83 25 90 01 04 00 03 c1 0f b7 f0 81 c1 90 01 04 8b c6 2b 45 90 01 01 83 e8 90 01 01 a3 90 01 04 0f b6 c2 8d 04 41 a3 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GP_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 ca ba 90 01 04 8b c1 2b 44 24 18 2d 90 01 04 66 39 15 90 01 04 90 18 83 c0 e1 2b cf 03 c8 81 c3 90 01 04 8b 44 24 90 01 01 83 44 24 90 01 01 04 89 0d 90 01 04 89 1d 90 01 04 89 18 8b 44 24 90 01 01 03 c1 ff 4c 24 90 01 01 0f b7 d0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}