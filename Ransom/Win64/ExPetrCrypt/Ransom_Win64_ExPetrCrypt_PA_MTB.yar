
rule Ransom_Win64_ExPetrCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/ExPetrCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 41 00 77 00 61 00 72 00 65 00 } //1 RansomAware
		$a_01_1 = {77 00 6f 00 72 00 74 00 68 00 20 00 6f 00 66 00 20 00 42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 20 00 74 00 6f 00 20 00 74 00 68 00 69 00 73 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 3a 00 } //1 worth of Bitcoin to this address:
		$a_01_2 = {4f 00 6f 00 6f 00 70 00 73 00 2c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 Ooops, your files have been encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}