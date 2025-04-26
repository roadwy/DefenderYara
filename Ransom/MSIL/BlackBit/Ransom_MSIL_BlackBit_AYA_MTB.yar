
rule Ransom_MSIL_BlackBit_AYA_MTB{
	meta:
		description = "Ransom:MSIL/BlackBit.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 66 00 6f 00 2e 00 42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 74 00 } //2 info.BlackBit
		$a_00_1 = {54 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 61 00 6e 00 64 00 20 00 61 00 6c 00 6c 00 20 00 6f 00 74 00 68 00 65 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 69 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 74 00 } //2 This file and all other files in your computer are encrypted by BlackBit
		$a_01_2 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 73 74 6f 72 65 20 74 68 69 73 20 66 69 6c 65 20 61 6e 64 20 72 65 73 74 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 50 6c 65 61 73 65 20 73 65 6e 64 20 75 73 20 6d 65 73 73 61 67 65 20 74 6f 20 74 68 69 73 20 65 2d 6d 61 69 6c } //1 If you want to restore this file and rest of your files, Please send us message to this e-mail
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}