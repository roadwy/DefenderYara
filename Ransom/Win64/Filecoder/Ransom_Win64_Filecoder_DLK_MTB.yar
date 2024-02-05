
rule Ransom_Win64_Filecoder_DLK_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.DLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 3b 34 80 44 24 3b 3f eb 18 c6 44 24 3d 57 80 44 24 3d 0d eb 1a c6 44 24 39 75 80 44 24 39 00 eb d5 c6 44 24 3c 2c eb 00 80 44 24 3c 3c } //00 00 
	condition:
		any of ($a_*)
 
}