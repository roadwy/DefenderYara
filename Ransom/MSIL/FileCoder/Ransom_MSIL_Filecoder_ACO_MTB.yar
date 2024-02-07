
rule Ransom_MSIL_Filecoder_ACO_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 22 07 08 72 99 0e 00 70 06 16 72 99 0e 00 70 28 5b 00 00 0a 6f 5c 00 00 0a 28 5d 00 00 0a 9d 08 17 58 0c 08 1f 10 32 d9 } //01 00 
		$a_01_1 = {53 00 65 00 6e 00 64 00 20 00 24 00 35 00 30 00 20 00 77 00 6f 00 72 00 74 00 68 00 20 00 6f 00 66 00 20 00 62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 20 00 74 00 6f 00 20 00 74 00 68 00 69 00 73 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 } //01 00  Send $50 worth of bitcoin to this address
		$a_01_2 = {4f 00 6f 00 6f 00 70 00 73 00 2c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  Ooops, your files have been encrypted
	condition:
		any of ($a_*)
 
}