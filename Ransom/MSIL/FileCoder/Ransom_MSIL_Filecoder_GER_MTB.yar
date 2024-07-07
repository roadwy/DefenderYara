
rule Ransom_MSIL_Filecoder_GER_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.GER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 74 20 74 68 65 20 6d 6f 6d 65 6e 74 2c 20 79 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 6e 6f 74 20 70 72 6f 74 65 63 74 65 64 } //At the moment, your system is not protected  1
		$a_80_1 = {57 65 20 63 61 6e 20 66 69 78 20 69 74 20 61 6e 64 20 72 65 73 74 6f 72 65 20 66 69 6c 65 73 2e } //We can fix it and restore files.  1
		$a_80_2 = {73 65 6e 64 20 61 20 66 69 6c 65 20 74 6f 20 64 65 63 72 79 70 74 20 74 72 69 61 6c } //send a file to decrypt trial  1
		$a_80_3 = {44 65 63 72 79 70 74 69 6f 6e 2e 68 65 6c 70 65 72 40 61 6f 6c 2e 63 6f 6d } //Decryption.helper@aol.com  1
		$a_80_4 = {44 65 63 72 79 70 74 69 6f 6e 2e 68 65 6c 70 40 63 79 62 65 72 66 65 61 72 2e 63 6f 6d } //Decryption.help@cyberfear.com  1
		$a_01_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}