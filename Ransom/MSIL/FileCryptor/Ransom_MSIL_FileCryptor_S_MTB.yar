
rule Ransom_MSIL_FileCryptor_S_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 61 6c 77 61 72 65 } //01 00  Malware
		$a_81_1 = {77 65 20 73 74 6f 6c 65 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 5a 20 61 6e 64 20 45 4e 43 52 59 54 50 45 44 20 54 48 45 4d } //01 00  we stole all your fileZ and ENCRYTPED THEM
		$a_81_2 = {54 68 69 73 20 69 73 20 6e 6f 74 20 79 6f 75 72 20 6c 75 63 6b 79 20 64 61 79 21 21 } //01 00  This is not your lucky day!!
		$a_81_3 = {2e 65 6e 63 72 79 70 74 65 64 } //01 00  .encrypted
		$a_81_4 = {2e 78 6c 73 78 } //01 00  .xlsx
		$a_81_5 = {2e 70 70 74 78 } //00 00  .pptx
	condition:
		any of ($a_*)
 
}