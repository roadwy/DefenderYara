
rule Ransom_MSIL_AvasCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/AvasCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_1 = {4e 00 6d 00 78 00 61 00 6f 00 79 00 69 00 73 00 } //1 Nmxaoyis
		$a_01_2 = {39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 31 00 34 00 32 00 2f 00 61 00 72 00 78 00 2d 00 58 00 6c 00 6f 00 70 00 66 00 5f 00 58 00 62 00 6b 00 71 00 6b 00 7a 00 6e 00 73 00 2e 00 70 00 6e 00 67 00 } //1 91.243.44.142/arx-Xlopf_Xbkqkzns.png
		$a_01_3 = {57 00 61 00 69 00 74 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00 20 00 7b 00 30 00 7d 00 } //1 Waiting... {0}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}