
rule Ransom_Win64_FileCoder_RHB_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e } //1 vssadmin
		$a_01_1 = {41 6c 62 61 62 61 74 2e 65 6b 65 79 41 6c 62 61 62 61 74 2e 6b 65 79 41 6c 62 61 62 61 74 5f 53 65 61 72 63 68 70 65 72 73 6f 6e 61 6c 5f 69 64 2e 74 78 74 } //1 Albabat.ekeyAlbabat.keyAlbabat_Searchpersonal_id.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 4b 45 59 } //1 Your files were encrypted with a KEY
		$a_01_3 = {42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN RSA PUBLIC KEY
		$a_03_4 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 25 00 ?? 0a 00 00 ?? 04 00 00 00 00 00 ?? ?? 0a 00 00 10 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=6
 
}