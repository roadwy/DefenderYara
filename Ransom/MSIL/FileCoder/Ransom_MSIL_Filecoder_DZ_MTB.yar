
rule Ransom_MSIL_Filecoder_DZ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00 
		$a_81_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_81_3 = {45 6e 63 72 79 70 74 32 } //01 00 
		$a_81_4 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}