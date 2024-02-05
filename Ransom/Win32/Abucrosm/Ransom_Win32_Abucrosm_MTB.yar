
rule Ransom_Win32_Abucrosm_MTB{
	meta:
		description = "Ransom:Win32/Abucrosm!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2a d3 80 c2 6d 88 15 90 01 04 8b 7c 24 14 8b 4c 24 10 8a d1 2a 15 90 01 04 88 54 24 0f 8b 3f 81 c7 90 01 04 89 3d 90 01 04 3d 90 01 04 75 90 02 60 2b c3 83 c0 19 0f b7 d0 8b 44 24 14 8b f2 89 38 90 00 } //01 00 
		$a_03_1 = {8b 7c 24 10 8a d8 2a 1d 90 01 04 8b 4c 24 20 80 c3 60 8b 54 24 1c 8b 3f 81 c7 90 01 04 89 15 90 01 04 83 f9 07 74 90 02 50 8a ca 2a c8 8d 41 08 8b 4c 24 10 89 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}