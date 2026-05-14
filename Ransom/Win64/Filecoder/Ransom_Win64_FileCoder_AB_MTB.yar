
rule Ransom_Win64_FileCoder_AB_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //3 s have been encrypted.C:\Windows\System32\svchost.exe
		$a_81_1 = {2e 63 63 6c 2e 74 6d 70 } //3 .ccl.tmp
		$a_81_2 = {42 65 73 74 20 52 65 67 61 72 64 73 20 2c 20 43 43 4c 61 6e 64 } //2 Best Regards , CCLand
		$a_81_3 = {43 3a 5c 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //2 C:\\Program Files\\Windows Defender
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=10
 
}
rule Ransom_Win64_FileCoder_AB_MTB_2{
	meta:
		description = "Ransom:Win64/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {21 21 21 52 45 41 44 4d 45 21 21 21 2e 74 78 74 } //1 !!!README!!!.txt
		$a_81_1 = {63 72 79 70 74 65 64 30 30 30 30 30 37 } //1 crypted000007
		$a_81_2 = {5c 2e 6e 6f 5f 6d 6f 72 65 5f 72 61 6e 73 6f 6d } //1 \.no_more_ransom
		$a_81_3 = {5c 74 61 73 6b 73 5c 68 64 64 69 64 6c 65 73 63 61 6e 2e 6a 6f 62 } //1 \tasks\hddidlescan.job
		$a_81_4 = {5c 61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 \aaa_TouchMeNot_.txt
		$a_81_5 = {2e 6b 65 79 62 74 63 40 67 6d 61 69 6c 5f 63 6f 6d } //1 .keybtc@gmail_com
		$a_81_6 = {2e 70 61 79 63 72 79 70 74 40 67 6d 61 69 6c 5f 63 6f 6d } //1 .paycrypt@gmail_com
		$a_81_7 = {2e 77 6e 63 72 79 } //1 .wncry
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Ransom_Win64_FileCoder_AB_MTB_3{
	meta:
		description = "Ransom:Win64/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 56 48 83 ec 20 48 8b f1 4c 8d 35 0d 58 ff ff 8b ea 44 8b d2 83 e5 04 41 81 e2 80 00 00 00 44 8b ca 41 8b f8 41 83 c9 01 f6 c2 40 44 0f 44 ca } //1
		$a_01_1 = {83 c9 02 41 f6 c1 08 41 0f 44 c9 45 33 c0 81 e1 3b ff ff ff 85 d2 } //1
		$a_01_2 = {75 10 48 c1 c1 10 66 f7 c1 ff ff 75 01 c3 48 c1 c9 10 } //1
		$a_01_3 = {4c 8d 35 0d 58 ff ff 8b ea 44 8b d2 83 e5 04 41 81 e2 80 00 00 00 44 8b ca } //1
		$a_01_4 = {f6 c2 40 44 0f 44 ca 8b 15 ef 57 03 00 41 8b c9 83 c9 02 41 f6 c1 08 41 0f 44 c9 45 33 c0 81 e1 3b ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}