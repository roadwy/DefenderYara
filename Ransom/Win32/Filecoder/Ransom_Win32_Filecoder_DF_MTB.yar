
rule Ransom_Win32_Filecoder_DF_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5f 5f 44 45 43 52 59 50 54 5f 4e 4f 54 45 5f 5f } //1 __DECRYPT_NOTE__
		$a_81_1 = {2e 45 58 54 45 4e } //1 .EXTEN
		$a_81_2 = {73 74 6f 70 6d 61 72 6b 65 72 } //1 stopmarker
		$a_81_3 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //1 FindFirstFileExW
		$a_81_4 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //1 FindNextFileW
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}