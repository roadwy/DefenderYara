
rule Ransom_MSIL_HakunaMatata_SWL_MTB{
	meta:
		description = "Ransom:MSIL/HakunaMatata.SWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {48 61 6b 75 6e 61 20 4d 61 74 61 74 61 20 32 2e 33 } //Hakuna Matata 2.3  2
		$a_80_1 = {23 45 4e 43 52 59 50 54 5f 45 58 54 45 4e 53 49 4f 4e 53 } //#ENCRYPT_EXTENSIONS  2
		$a_80_2 = {24 64 34 64 35 34 63 37 33 2d 63 34 34 32 2d 34 66 38 61 2d 61 39 34 63 2d 36 31 34 63 62 65 37 32 38 32 66 33 } //$d4d54c73-c442-4f8a-a94c-614cbe7282f3  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}