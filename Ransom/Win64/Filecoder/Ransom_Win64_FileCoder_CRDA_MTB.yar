
rule Ransom_Win64_FileCoder_CRDA_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.CRDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 5f 64 61 74 65 2e 74 78 74 } //1 encrypt_date.txt
		$a_01_1 = {50 65 74 65 72 27 73 52 61 6e 73 6f 6d 77 61 72 65 } //1 Peter'sRansomware
		$a_01_2 = {45 6c 65 76 61 74 65 64 21 21 21 20 59 61 79 } //1 Elevated!!! Yay
		$a_01_3 = {46 61 69 6c 20 74 6f 20 65 6e 63 72 79 70 74 } //1 Fail to encrypt
		$a_01_4 = {2e 37 7a 2e 72 61 72 2e 6d 34 61 2e 77 6d 61 2e 61 76 69 2e 77 6d 76 2e 64 33 64 62 73 70 2e 73 63 32 73 61 76 65 } //1 .7z.rar.m4a.wma.avi.wmv.d3dbsp.sc2save
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}