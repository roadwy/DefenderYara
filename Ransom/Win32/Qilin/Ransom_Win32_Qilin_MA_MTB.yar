
rule Ransom_Win32_Qilin_MA_MTB{
	meta:
		description = "Ransom:Win32/Qilin.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 79 6f 75 20 6d 6f 64 69 66 79 20 66 69 6c 65 73 20 2d 20 6f 75 72 20 64 65 63 72 79 70 74 20 73 6f 66 74 77 61 72 65 20 77 6f 6e 27 74 20 61 62 6c 65 20 74 6f 20 72 65 63 6f 76 65 72 20 64 61 74 61 20 } //1 If you modify files - our decrypt software won't able to recover data 
		$a_01_1 = {57 65 20 68 61 76 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 63 6f 6d 70 72 6f 6d 69 73 69 6e 67 20 61 6e 64 20 73 65 6e 73 69 74 69 76 65 20 64 61 74 61 20 66 72 6f 6d 20 79 6f 75 } //1 We have downloaded compromising and sensitive data from you
		$a_01_2 = {2e 52 45 41 44 4d 45 2d 52 45 43 4f 56 45 52 2d 2e 74 78 74 } //1 .README-RECOVER-.txt
		$a_01_3 = {74 6f 20 68 65 6c 70 20 79 6f 75 20 67 65 74 20 74 68 65 20 63 69 70 68 65 72 20 6b 65 79 2e 20 57 65 20 65 6e 63 6f 75 72 61 67 65 20 79 6f 75 20 74 6f 20 63 6f 6e 73 69 64 65 72 20 79 6f 75 72 20 64 65 63 69 73 69 6f 6e 73 } //1 to help you get the cipher key. We encourage you to consider your decisions
		$a_01_4 = {2d 2d 20 43 72 65 64 65 6e 74 69 61 6c 73 20 } //1 -- Credentials 
		$a_01_5 = {2d 2d 20 51 69 6c 69 6e } //1 -- Qilin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}