
rule Ransom_Win64_Nokoyawa_BA{
	meta:
		description = "Ransom:Win64/Nokoyawa.BA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b c2 4d 8d 40 90 01 01 33 c2 81 c2 90 01 04 69 c8 90 01 04 81 f1 90 01 04 8b c1 c1 e8 0d 33 c1 69 c8 90 01 04 8b c1 c1 e8 0f 33 c1 41 89 40 fc 49 83 e9 01 75 90 00 } //01 00 
		$a_01_1 = {4e 4f 4b 4f 59 41 57 41 20 76 32 2e 30 2e 70 64 62 } //00 00  NOKOYAWA v2.0.pdb
	condition:
		any of ($a_*)
 
}