
rule Trojan_Win32_Gozi_BC_MTB{
	meta:
		description = "Trojan:Win32/Gozi.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b fa 89 44 24 10 8b 44 24 30 02 db 03 44 24 34 2a df 8b 15 90 01 04 80 eb 50 8b 74 24 24 2b d0 8b 44 24 28 02 d9 81 3d 90 01 04 21 0b 00 00 89 15 90 01 04 8b 34 30 75 1c 83 3d 90 01 04 00 75 13 2b 15 90 01 04 8a da 89 15 90 01 04 02 db 80 c3 0d 8b 54 24 28 8a c1 2a 44 24 10 81 c6 04 9c 01 01 2c 52 89 35 90 01 04 02 d8 8b 44 24 24 89 34 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}