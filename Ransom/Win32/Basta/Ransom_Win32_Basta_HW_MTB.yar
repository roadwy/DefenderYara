
rule Ransom_Win32_Basta_HW_MTB{
	meta:
		description = "Ransom:Win32/Basta.HW!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 66 62 6a 64 66 76 73 6c 73 64 } //1 dfbjdfvslsd
		$a_01_1 = {76 43 79 51 4f 44 70 4c 4d 6d 49 59 66 49 47 54 49 4a 4a 76 69 5a 76 45 69 6d 45 62 6b 74 63 75 41 41 5a 77 4c 66 4f 7a 53 68 4b 74 52 71 73 62 6f 59 46 55 6f 70 6c 78 75 58 64 69 79 67 51 72 45 } //1 vCyQODpLMmIYfIGTIJJviZvEimEbktcuAAZwLfOzShKtRqsboYFUoplxuXdiygQrE
		$a_01_2 = {45 3a 5c 63 70 70 5c 6f 75 74 5c 6f 75 74 5c 6f 75 74 2e 70 64 62 } //1 E:\cpp\out\out\out.pdb
		$a_01_3 = {44 65 66 65 6e 64 65 72 20 75 70 64 61 74 65 20 73 65 72 76 69 63 65 20 6c 6f 63 61 6c 20 74 79 70 65 } //1 Defender update service local type
		$a_01_4 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 32 00 30 00 30 00 33 00 2d 00 32 00 30 00 32 00 32 00 20 00 47 00 6c 00 61 00 72 00 79 00 73 00 6f 00 66 00 74 00 20 00 4c 00 74 00 64 00 } //1 Copyright (c) 2003-2022 Glarysoft Ltd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}