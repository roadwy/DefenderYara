
rule Ransom_MSIL_Filecoder_AKD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 7b 12 00 00 04 72 2c 06 00 70 28 ?? 00 00 06 6f 4a 00 00 0a 72 3a 06 00 70 28 ?? 00 00 0a 6f 4a 00 00 0a 72 48 06 00 70 28 ?? 00 00 06 6f 4c 00 00 0a 6f 4d 00 00 0a 6f 4a 00 00 0a 72 52 06 00 70 72 66 06 00 70 6f 4a 00 00 0a 28 ?? 00 00 0a 11 09 17 d6 13 09 } //3
		$a_01_1 = {03 28 64 00 00 0a 0a 02 06 05 28 1a 00 00 06 0b 04 07 28 65 00 00 0a de 0e } //3
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}