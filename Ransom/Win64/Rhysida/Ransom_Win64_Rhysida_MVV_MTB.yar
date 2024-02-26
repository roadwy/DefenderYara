
rule Ransom_Win64_Rhysida_MVV_MTB{
	meta:
		description = "Ransom:Win64/Rhysida.MVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 0f b6 2c 0a 83 c0 90 01 01 47 30 2c 0f 43 0f b6 2c 02 41 0f b6 0c 12 43 30 2c 07 45 0f b6 0c 3a 41 30 0c 17 45 30 0c 3f 39 c6 77 90 00 } //01 00 
		$a_03_1 = {43 0f b6 0c 2a 45 30 04 3b 8d 78 90 01 01 43 30 0c 2b 44 8d 68 06 41 0f b6 2c 12 41 30 2c 13 8d 50 90 01 01 83 c0 08 45 0f b6 04 3a 43 0f b6 0c 2a 45 30 04 3b 41 0f b6 2c 12 43 30 0c 2b 41 30 2c 13 41 39 c6 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}