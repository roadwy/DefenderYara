
rule Ransom_Win32_Basta_AF_MTB{
	meta:
		description = "Ransom:Win32/Basta.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7d 1a 8b 45 c4 03 45 d4 8b 4d 90 01 01 8a 54 0d 90 01 01 88 10 8b 45 d4 83 c0 01 89 45 d4 90 13 90 02 20 8b 55 f0 83 90 01 01 01 90 00 } //01 00 
		$a_03_1 = {8b 55 f0 83 c2 01 89 55 f0 83 7d f0 03 7d 1a 8b 45 d0 03 45 e0 8b 4d f0 8a 54 0d e4 88 10 8b 45 e0 83 c0 01 89 45 e0 90 13 8b 55 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}