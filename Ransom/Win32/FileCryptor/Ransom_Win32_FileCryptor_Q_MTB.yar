
rule Ransom_Win32_FileCryptor_Q_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 43 50 83 ef 10 8b 55 fc 0f b7 4b 5a c1 e0 10 33 c8 33 0a 33 4b 44 89 0e 8b 43 58 0f b7 4b 62 c1 e0 10 33 c8 33 4a 04 33 4b 4c 89 4e 04 8b 43 60 0f b7 4b 4a c1 e0 10 33 c8 33 4a 08 } //1
		$a_01_1 = {8b 7b 20 03 3b 0f b7 cf 8b d7 c1 ea 10 8b f1 0f af f1 8b c2 0f af c1 0f af d2 0f af ff c1 ee 11 03 f0 8b 45 f4 c1 ee 0f 03 f2 33 f7 83 6d fc 01 89 34 18 8d 5b 04 75 c8 } //1
		$a_01_2 = {8d 4d e8 03 cf 8a 04 08 32 01 47 88 04 0a 8b 45 fc 3b fe 72 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}