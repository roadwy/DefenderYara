
rule Ransom_Win32_StopCrypt_PBC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 e2 8b 4d 90 01 01 8b c6 d3 e8 03 95 90 01 04 89 45 90 01 01 8b 85 90 01 04 01 45 90 01 01 83 25 90 01 04 00 8d 04 37 33 45 90 01 01 33 d0 8b ca 8d 85 90 01 04 e8 90 01 04 81 c7 47 86 c8 61 ff 8d 90 01 04 0f 85 90 00 } //01 00 
		$a_03_1 = {8b ce c1 e9 05 c7 05 90 02 0a 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b c6 c1 e0 04 03 44 24 90 01 01 8d 14 33 33 c2 33 44 24 90 01 01 81 c3 47 86 c8 61 2b f8 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}