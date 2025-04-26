
rule Ransom_MSIL_Filecoder_FJ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your files have been encrypted
		$a_81_1 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_2 = {42 54 43 20 74 6f 20 74 68 65 20 61 64 64 72 65 73 73 } //1 BTC to the address
		$a_81_3 = {44 65 63 72 79 70 74 69 6f 6e 20 50 72 6f 63 63 65 73 73 20 68 61 73 20 62 65 67 75 6e } //1 Decryption Proccess has begun
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}