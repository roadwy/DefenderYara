
rule Ransom_MSIL_Bert_A{
	meta:
		description = "Ransom:MSIL/Bert.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 66 00 72 00 6f 00 6d 00 20 00 42 00 65 00 72 00 74 00 21 00 } //1 Hello from Bert!
		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 62 00 79 00 62 00 65 00 72 00 74 00 } //1 encryptedbybert
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}