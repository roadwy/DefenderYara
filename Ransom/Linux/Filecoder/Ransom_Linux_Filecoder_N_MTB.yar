
rule Ransom_Linux_Filecoder_N_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 65 74 61 45 6e 63 72 79 70 74 65 72 2e 74 78 74 } //1 MetaEncrypter.txt
		$a_01_1 = {2d 2d 64 69 73 61 62 6c 65 2d 72 61 6e 73 6f 6d 66 69 6c 65 } //1 --disable-ransomfile
		$a_01_2 = {2e 6d 65 74 65 6e 63 72 79 70 74 65 64 } //1 .metencrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}