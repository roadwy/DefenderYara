
rule Ransom_MSIL_Small_B_MTB{
	meta:
		description = "Ransom:MSIL/Small.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files are encrypted
		$a_81_1 = {65 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //01 00  extensionsToEncrypt
		$a_81_2 = {44 69 72 65 63 74 6f 72 69 65 73 54 6f 45 6e 63 72 79 70 74 } //01 00  DirectoriesToEncrypt
		$a_81_3 = {2e 58 65 72 6f 67 } //00 00  .Xerog
	condition:
		any of ($a_*)
 
}