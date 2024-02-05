
rule Ransom_Win64_Knight_ZA_MTB{
	meta:
		description = "Ransom:Win64/Knight.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 c8 ff c3 48 b8 90 02 0a 48 f7 e1 48 c1 ea 90 01 01 48 6b c2 90 01 01 48 2b c8 0f be 44 0c 90 01 01 66 41 89 06 4d 8d 76 90 01 01 3b 9c 24 90 01 04 72 90 00 } //01 00 
		$a_03_1 = {42 8a 4c 04 90 01 01 41 8d 40 90 01 01 41 30 09 45 33 c0 49 ff c1 83 f8 90 01 01 44 0f 45 c0 49 83 ea 90 01 01 75 90 00 } //01 00 
		$a_03_2 = {47 00 45 00 c7 90 01 02 54 00 00 00 ff 90 00 } //01 00 
		$a_03_3 = {73 00 3a 00 90 02 0a 2f 00 2f 00 e8 90 01 02 00 00 81 3b 68 74 74 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}