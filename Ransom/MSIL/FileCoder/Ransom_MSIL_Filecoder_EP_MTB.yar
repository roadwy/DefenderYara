
rule Ransom_MSIL_Filecoder_EP_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 50 63 20 69 73 20 48 61 63 6b 65 64 } //01 00 
		$a_81_1 = {74 65 73 74 2e 74 78 74 } //01 00 
		$a_81_2 = {4d 65 73 73 61 67 65 20 74 6f 20 62 65 20 77 72 69 74 74 65 6e 20 69 6e 20 74 65 73 74 2e 74 78 74 } //01 00 
		$a_81_3 = {65 72 61 77 6f 73 6e 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}