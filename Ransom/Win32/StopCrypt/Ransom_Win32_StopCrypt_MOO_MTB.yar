
rule Ransom_Win32_StopCrypt_MOO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 54 24 20 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d 90 01 04 8c 07 00 00 c7 05 90 01 04 00 00 00 00 89 4c 24 10 75 90 00 } //01 00 
		$a_03_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d 4c 1c 2e 02 93 00 00 00 75 90 01 01 68 90 01 04 8d 44 24 78 50 ff 15 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}