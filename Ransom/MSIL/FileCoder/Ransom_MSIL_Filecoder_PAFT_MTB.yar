
rule Ransom_MSIL_Filecoder_PAFT_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 65 72 69 6e 46 75 73 63 61 74 6f 72 } //2 XerinFuscator
		$a_01_1 = {4b 2e 47 2e 42 20 2d 20 42 75 72 68 61 6e 20 41 6c 61 73 73 61 64 } //2 K.G.B - Burhan Alassad
		$a_01_2 = {24 33 32 32 34 31 66 66 64 2d 62 66 61 36 2d 34 35 30 31 2d 39 38 62 31 2d 61 38 31 38 62 33 30 63 33 64 65 37 } //2 $32241ffd-bfa6-4501-98b1-a818b30c3de7
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}