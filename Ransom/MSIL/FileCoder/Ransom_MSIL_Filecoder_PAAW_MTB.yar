
rule Ransom_MSIL_Filecoder_PAAW_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 11 04 91 08 11 04 08 8e 69 5d 91 11 04 04 d6 08 8e 69 d6 1d 5f 62 d2 20 ff 00 00 00 5f 61 b4 9c 11 04 17 d6 13 04 11 04 09 31 d1 } //01 00 
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //01 00 
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}