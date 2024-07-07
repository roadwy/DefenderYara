
rule Ransom_Win32_Filecoder_FE_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 } //1 How To Decrypt Files
		$a_81_1 = {64 6f 6e 74 63 72 79 70 74 61 6e 79 77 61 79 } //1 dontcryptanyway
		$a_81_2 = {68 65 6c 70 6d 65 64 65 63 6f 64 65 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 helpmedecode@tutanota.com
		$a_81_3 = {64 65 63 72 79 70 74 69 6f 6e 65 72 40 61 69 72 6d 61 69 6c 2e 63 63 } //1 decryptioner@airmail.cc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}