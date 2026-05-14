
rule Ransom_MSIL_PadCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/PadCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 5f 00 68 00 74 00 6d 00 6c 00 } //4 ransom_html
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 6e 64 20 64 6f 63 75 6d 65 6e 74 73 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files and documents on this computer have been encrypted
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}