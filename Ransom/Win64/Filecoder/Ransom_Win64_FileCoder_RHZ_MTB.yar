
rule Ransom_Win64_FileCoder_RHZ_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //3 -----BEGIN PUBLIC KEY-----
		$a_01_1 = {2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----END PUBLIC KEY-----
		$a_01_2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_3 = {73 33 2e 64 75 61 6c 73 74 61 63 6b 2e 75 73 } //1 s3.dualstack.us
		$a_00_4 = {62 00 63 00 72 00 79 00 70 00 74 00 70 00 72 00 69 00 6d 00 69 00 74 00 69 00 76 00 65 00 73 00 } //1 bcryptprimitives
		$a_01_5 = {76 73 73 61 64 6d 69 6e } //1 vssadmin
		$a_01_6 = {2e 62 61 63 6b } //1 .back
		$a_01_7 = {2e 70 70 74 78 } //1 .pptx
		$a_03_8 = {50 45 00 00 64 86 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*2) >=12
 
}