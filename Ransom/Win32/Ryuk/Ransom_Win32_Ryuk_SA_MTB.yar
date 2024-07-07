
rule Ransom_Win32_Ryuk_SA_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 53 42 68 76 53 57 43 76 46 52 76 66 43 66 41 6f 4a 64 6f 46 75 41 55 6d 4b } //2 CSBhvSWCvFRvfCfAoJdoFuAUmK
		$a_81_1 = {51 6b 6b 62 61 6c } //1 Qkkbal
		$a_03_2 = {8d 76 00 8b 1c 90 01 01 8b 2c 90 01 01 81 e5 7f 7f 7f 7f 89 de 81 e6 7f 7f 7f 7f 01 ee 33 1c 90 01 01 81 e3 80 80 80 80 31 de 89 90 01 02 47 39 90 01 03 77 90 00 } //1
		$a_03_3 = {0f b6 c0 0f b6 12 01 d0 31 d2 f7 f5 8a 90 01 03 8b 90 01 03 02 04 90 01 01 8b 90 01 03 32 04 90 01 01 8b 90 01 03 88 04 90 01 01 47 3b 90 01 03 75 90 00 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}