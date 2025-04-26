
rule Ransom_Win64_FileCoder_AYH_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 77 69 6c 6c 20 65 6e 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 61 6e 64 20 63 61 6e 6e 6f 74 20 62 65 20 72 65 63 6f 76 65 72 65 64 2e 20 41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 75 6e 20 69 74 3f } //2 This program will encrypt your files and cannot be recovered. Are you sure you want to run it?
		$a_01_1 = {45 4e 43 4f 44 45 52 20 41 4c 4c } //1 ENCODER ALL
		$a_01_2 = {46 69 6e 61 6c 20 77 61 72 6e 69 6e 67 2c 20 61 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 75 6e 3f } //1 Final warning, are you sure you want to run?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}