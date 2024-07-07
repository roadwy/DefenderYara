
rule Ransom_MSIL_Janelle_PAA_MTB{
	meta:
		description = "Ransom:MSIL/Janelle.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 important files are encrypted
		$a_01_1 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 4b 00 65 00 79 00 2e 00 74 00 78 00 74 00 } //1 EncryptedKey.txt
		$a_01_2 = {2e 00 4a 00 41 00 4e 00 45 00 4c 00 4c 00 45 00 } //1 .JANELLE
		$a_01_3 = {76 00 69 00 72 00 75 00 73 00 } //1 virus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}