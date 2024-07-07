
rule Ransom_MSIL_Cryptolocker_PAC_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 50 4f 43 } //1 RansomwarePOC
		$a_81_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 All of your files have been encrypted.
		$a_81_2 = {4e 6f 20 66 69 6c 65 73 20 74 6f 20 46 55 43 4b 2e } //1 No files to FUCK.
		$a_81_3 = {52 45 41 44 5f 54 48 49 53 5f 54 4f 5f 44 45 43 52 59 50 54 2e } //1 READ_THIS_TO_DECRYPT.
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}