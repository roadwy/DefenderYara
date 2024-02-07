
rule Ransom_MSIL_Filecoder_PAAR_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 8f 1a 00 00 01 25 47 02 7e 03 00 00 04 11 04 5a 28 90 01 03 06 d2 61 d2 52 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 05 11 05 2d cf 90 00 } //01 00 
		$a_01_1 = {52 61 6e 53 6f 6d 2e 70 64 62 } //00 00  RanSom.pdb
	condition:
		any of ($a_*)
 
}