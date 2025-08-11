
rule Ransom_Win64_RoundeRan_YAE_MTB{
	meta:
		description = "Ransom:Win64/RoundeRan.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 } //10 Your files are currently encrypted
		$a_01_1 = {64 65 63 72 79 70 74 6f 72 20 6b 65 79 } //1 decryptor key
		$a_01_2 = {72 65 73 75 6c 74 20 69 6e 20 64 61 74 61 20 6c 6f 73 73 } //1 result in data loss
		$a_01_3 = {72 65 73 74 6f 72 65 20 73 6f 6d 65 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 } //1 restore some files for free
		$a_01_4 = {64 61 74 61 20 74 6f 20 62 65 20 6c 6f 73 74 20 66 6f 72 65 76 65 72 } //1 data to be lost forever
		$a_01_5 = {64 61 74 61 20 6c 65 61 6b 73 } //1 data leaks
		$a_01_6 = {67 65 74 20 69 6e 74 6f 20 74 68 65 20 6d 65 64 69 61 } //1 get into the media
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}