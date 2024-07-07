
rule Trojan_BAT_NjRat_NEBZ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 38 65 38 65 37 39 63 2d 33 36 32 34 2d 34 61 32 33 2d 39 36 63 65 2d 32 62 35 64 35 32 63 61 66 36 66 66 } //5 f8e8e79c-3624-4a23-96ce-2b5d52caf6ff
		$a_01_1 = {6e 65 77 65 6e 63 2e 65 78 65 } //5 newenc.exe
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_01_4 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}