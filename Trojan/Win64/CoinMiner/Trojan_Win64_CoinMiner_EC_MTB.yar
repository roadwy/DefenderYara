
rule Trojan_Win64_CoinMiner_EC_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 89 45 d8 41 0f ba e0 09 41 8b c7 45 8b c3 45 8b cc 0f a2 45 0f 43 c7 45 33 d2 89 45 d0 89 5d d4 89 4d d8 33 c9 89 55 dc 41 8b c7 0f a2 41 0f ba e2 09 4c 89 55 d0 } //4
		$a_01_1 = {4c 8d 65 d0 4c 8b eb 4d 03 e0 49 f7 dc 49 f7 dd 43 8d 04 16 30 03 85 c9 75 41 } //3
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}
rule Trojan_Win64_CoinMiner_EC_MTB_2{
	meta:
		description = "Trojan:Win64/CoinMiner.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 30 36 39 34 30 36 33 2e 78 73 70 68 2e 72 75 2f 47 50 55 36 2e 7a 69 70 } //1 a0694063.xsph.ru/GPU6.zip
		$a_81_1 = {61 30 36 39 34 30 36 33 2e 78 73 70 68 2e 72 75 2f 55 70 53 79 73 2e 65 78 65 } //1 a0694063.xsph.ru/UpSys.exe
		$a_81_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 44 61 74 61 5c 47 50 55 2e 7a 69 70 } //1 C:\ProgramData\Data\GPU.zip
		$a_81_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 55 70 53 79 73 2e 65 78 65 } //1 C:\ProgramData\UpSys.exe
		$a_81_4 = {4e 61 6d 65 20 57 69 6e 4e 65 74 20 2d 50 72 6f 70 65 72 74 79 54 79 70 65 20 53 74 72 69 6e 67 20 2d 56 61 6c 75 65 } //1 Name WinNet -PropertyType String -Value
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}