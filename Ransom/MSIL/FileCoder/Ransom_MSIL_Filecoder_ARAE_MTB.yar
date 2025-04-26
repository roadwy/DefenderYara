
rule Ransom_MSIL_Filecoder_ARAE_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //All of your files are encrypted  2
		$a_80_1 = {54 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //To unlock your files  2
		$a_80_2 = {4a 75 73 74 20 73 65 6e 64 20 6d 65 20 3a } //Just send me :  2
		$a_80_3 = {42 69 74 63 6f 69 6e } //Bitcoin  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}
rule Ransom_MSIL_Filecoder_ARAE_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 69 20 79 6f 75 20 61 72 65 20 68 61 63 6b 65 64 } //hi you are hacked  2
		$a_80_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //All your files are encrypted  2
		$a_80_2 = {46 69 6c 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 21 } //File encryption successful!  2
		$a_01_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //2 EncryptFile
		$a_01_4 = {52 43 34 45 6e 63 72 79 70 74 } //2 RC4Encrypt
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}