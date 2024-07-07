
rule Ransom_MSIL_LockyCrypt_PB_MTB{
	meta:
		description = "Ransom:MSIL/LockyCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 79 00 } //1 .locky
		$a_01_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2d 00 6c 00 6f 00 63 00 6b 00 79 00 2e 00 74 00 78 00 74 00 } //1 readme-locky.txt
		$a_01_2 = {46 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 6c 00 6f 00 63 00 6b 00 79 00 } //1 Files has been encrypted with locky
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}