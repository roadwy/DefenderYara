
rule Ransom_MSIL_Filecoder_PG_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 79 00 70 00 74 00 6f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //01 00  CryptoRansomware
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 68 00 6f 00 75 00 63 00 65 00 6d 00 6a 00 6f 00 75 00 69 00 6e 00 69 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 70 00 72 00 6f 00 6a 00 65 00 74 00 20 00 73 00 61 00 6e 00 73 00 20 00 66 00 69 00 6c 00 73 00 5c 00 74 00 65 00 73 00 74 00 } //01 00  C:\Users\houcemjouini\Desktop\projet sans fils\test
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 61 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  Your all files are encrypted
		$a_01_3 = {5c 43 72 79 70 74 6f 53 6f 6d 77 61 72 65 2e 70 64 62 } //00 00  \CryptoSomware.pdb
	condition:
		any of ($a_*)
 
}