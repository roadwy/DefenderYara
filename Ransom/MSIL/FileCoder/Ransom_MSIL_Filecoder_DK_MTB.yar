
rule Ransom_MSIL_Filecoder_DK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 6f 6b 73 20 6c 69 6b 65 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Looks like your files are encrypted
		$a_81_1 = {4b 69 6c 6c 20 73 77 69 74 63 68 20 61 63 74 69 76 61 74 65 64 21 } //1 Kill switch activated!
		$a_81_2 = {53 74 61 72 74 69 6e 67 20 66 61 6b 65 20 73 76 63 68 6f 73 74 2e 65 78 65 2e 2e 2e } //1 Starting fake svchost.exe...
		$a_81_3 = {49 6e 66 65 63 74 69 6e 67 20 63 6f 6d 70 75 74 65 72 2e 2e 2e } //1 Infecting computer...
		$a_81_4 = {69 20 77 69 6c 6c 20 72 65 6d 6f 76 65 20 79 6f 75 72 20 6b 65 79 20 66 6f 72 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 77 68 69 63 68 20 6d 65 61 6e 73 20 74 68 61 74 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 67 6f 6e 65 21 } //1 i will remove your key for your encrypted files which means that your files are gone!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}