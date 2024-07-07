
rule Ransom_MSIL_Filecoder_PAAS_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 6b 6b 69 74 20 76 31 5c 4c 6f 6b 6b 69 74 20 76 31 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4c 6f 6b 6b 69 74 20 76 31 2e 70 64 62 } //1 Lokkit v1\Lokkit v1\obj\Release\Lokkit v1.pdb
		$a_01_1 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 4c 00 62 00 6c 00 31 00 } //1 ransomLbl1
		$a_01_2 = {44 00 65 00 61 00 72 00 20 00 75 00 73 00 65 00 72 00 2c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 63 00 6f 00 6d 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 20 00 54 00 68 00 65 00 79 00 20 00 61 00 72 00 65 00 20 00 6e 00 6f 00 77 00 20 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 63 00 61 00 6e 00 27 00 74 00 20 00 62 00 65 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 65 00 64 00 20 00 75 00 6e 00 74 00 69 00 6c 00 20 00 79 00 6f 00 75 00 20 00 70 00 61 00 79 00 20 00 6f 00 75 00 72 00 20 00 66 00 65 00 65 00 2e 00 } //1 Dear user, your files have become encrypted. They are now locked and can't be recovered until you pay our fee.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}