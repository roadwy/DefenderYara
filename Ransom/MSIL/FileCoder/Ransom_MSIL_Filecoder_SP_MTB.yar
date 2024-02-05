
rule Ransom_MSIL_Filecoder_SP_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 08 17 58 0c 08 1f 0a 32 f0 90 0a 10 00 07 06 6f 90 00 } //01 00 
		$a_81_1 = {77 68 69 74 65 5f 72 61 6e 73 6f 6d 65 77 61 72 65 } //01 00 
		$a_01_2 = {77 00 68 00 69 00 74 00 65 00 2e 00 6a 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}