
rule Ransom_Win32_Stopcrypt_YAC_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 18 8d 34 17 d3 ea 8b 4c 24 10 8d 04 19 33 c6 03 d5 81 3d 90 01 08 8b fa 89 44 24 90 00 } //01 00 
		$a_03_1 = {c7 04 24 00 00 00 00 8b 44 24 10 89 04 24 8b 44 24 0c 31 04 24 8b 04 24 8b 4c 24 90 01 01 89 01 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}