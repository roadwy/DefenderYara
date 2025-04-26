
rule Ransom_MSIL_Filecoder_EW_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2e } //1 All your files are encrypted.
		$a_81_1 = {70 61 73 73 77 6f 72 64 31 32 33 } //1 password123
		$a_81_2 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //1 Rasomware2.0
		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}