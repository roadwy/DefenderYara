
rule Ransom_MSIL_Filecoder_EZ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {21 52 45 41 44 4d 45 21 2e 68 74 61 } //01 00 
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00 
		$a_81_2 = {6c 6f 63 6b 66 69 6c 65 } //01 00 
		$a_81_3 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}