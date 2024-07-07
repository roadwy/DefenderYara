
rule Ransom_MSIL_Filecoder_AFC_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 24 00 09 11 04 8f 90 01 03 01 25 47 02 7e 90 01 03 04 11 04 5a 28 90 01 03 06 d2 61 d2 52 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 90 00 } //2
		$a_01_1 = {66 6c 6f 78 65 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 52 61 6e 53 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 61 6e 53 6f 6d 2e 70 64 62 } //1 floxen\source\repos\RanSom\obj\Debug\RanSom.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}