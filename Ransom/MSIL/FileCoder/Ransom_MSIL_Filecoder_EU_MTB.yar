
rule Ransom_MSIL_Filecoder_EU_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_1 = {67 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } //01 00 
		$a_81_2 = {61 65 73 4b 65 79 } //01 00 
		$a_81_3 = {62 79 74 65 5f 63 69 70 68 65 72 74 65 78 74 } //01 00 
		$a_81_4 = {65 6e 63 72 79 70 74 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}