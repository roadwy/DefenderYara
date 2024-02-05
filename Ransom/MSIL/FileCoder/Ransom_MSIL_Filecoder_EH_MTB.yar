
rule Ransom_MSIL_Filecoder_EH_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 2e 65 78 65 } //01 00 
		$a_81_1 = {46 72 65 65 7a 65 4d 6f 75 73 65 } //01 00 
		$a_81_2 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00 
		$a_81_3 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}