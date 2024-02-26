
rule Ransom_MSIL_FileCoder_MVF_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 63 72 79 70 74 65 72 } //01 00  Encrypter
		$a_80_1 = {53 65 6e 64 20 45 6d 61 69 6c 20 54 6f 20 62 6f 74 68 20 41 64 64 72 65 73 73 } //Send Email To both Address  01 00 
		$a_80_2 = {74 6f 20 6b 69 6c 6c 20 74 68 65 20 72 61 6e 73 6f 6d 77 61 72 65 } //to kill the ransomware  01 00 
		$a_80_3 = {42 45 46 4f 52 45 20 44 45 43 52 59 50 54 49 4e 47 20 54 45 53 54 20 46 49 4c 45 } //BEFORE DECRYPTING TEST FILE  00 00 
	condition:
		any of ($a_*)
 
}