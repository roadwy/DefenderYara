
rule Ransom_Win32_TeslaCrypt_AA_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 8b 44 24 90 01 01 c7 44 24 90 01 05 c7 44 24 90 01 05 66 35 90 01 02 66 89 44 24 90 01 01 66 8b 44 24 90 01 01 66 35 90 01 02 8b 4c 24 90 01 01 66 8b 54 24 90 01 01 89 4c 24 90 01 01 66 39 c2 77 90 01 01 e9 90 01 04 b8 90 01 04 8b 4c 24 90 01 01 0f be 4c 0c 90 01 01 8b 54 24 90 01 01 8a 5c 24 90 01 01 2a 5c 24 90 01 01 29 d0 31 c1 88 cf 88 5c 24 90 01 01 8b 44 24 90 01 01 88 7c 04 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}