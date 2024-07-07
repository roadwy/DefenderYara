
rule Ransom_MSIL_Filecoder_DL_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 4f 57 5f 54 4f 5f 44 45 43 59 50 48 45 52 5f 46 49 4c 45 53 2e 74 78 74 } //1 HOW_TO_DECYPHER_FILES.txt
		$a_81_1 = {48 4f 57 5f 54 4f 5f 44 45 43 59 50 48 45 52 5f 46 49 4c 45 53 2e 68 74 61 } //1 HOW_TO_DECYPHER_FILES.hta
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 } //1 taskkill.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}