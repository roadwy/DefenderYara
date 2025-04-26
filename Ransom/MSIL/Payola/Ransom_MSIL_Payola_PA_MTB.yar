
rule Ransom_MSIL_Payola_PA_MTB{
	meta:
		description = "Ransom:MSIL/Payola.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 50 00 61 00 79 00 6f 00 6c 00 61 00 } //1 .Payola
		$a_01_1 = {52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 5f 00 47 00 75 00 69 00 64 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 Recovery_Guide.html
		$a_01_2 = {5c 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 5f 00 49 00 44 00 2e 00 74 00 78 00 74 00 } //1 \Recovery_ID.txt
		$a_01_3 = {46 00 69 00 6c 00 65 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //1 File Encrypted:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}