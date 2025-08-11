
rule Ransom_MSIL_Filecoder_PAGM_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAGM!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 65 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2c 00 20 00 67 00 6f 00 6f 00 64 00 20 00 6c 00 75 00 63 00 6b 00 2c 00 20 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 3a 00 20 00 78 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 } //2 All your files were encrypted, good luck, discord: xcrypter.
		$a_01_1 = {2e 00 78 00 63 00 72 00 79 00 70 00 74 00 } //2 .xcrypt
		$a_01_2 = {62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 } //1 background
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}