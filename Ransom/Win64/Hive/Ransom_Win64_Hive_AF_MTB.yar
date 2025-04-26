
rule Ransom_Win64_Hive_AF_MTB{
	meta:
		description = "Ransom:Win64/Hive.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 0f b6 24 39 41 31 fc 4d 39 d0 77 } //2
		$a_01_1 = {48 34 46 41 72 34 6c 51 6c 75 4d 36 51 50 57 65 56 32 64 31 2f 4c 59 5f 42 42 66 75 47 51 62 59 52 75 57 6a 34 4b 50 76 44 2f 36 39 71 56 4a 2d 56 48 56 37 4c 6b 44 41 4d 50 7a 77 39 46 2f 50 64 47 67 43 6d 71 61 34 32 55 71 35 74 4b 30 55 73 52 67 } //1 H4FAr4lQluM6QPWeV2d1/LY_BBfuGQbYRuWj4KPvD/69qVJ-VHV7LkDAMPzw9F/PdGgCmqa42Uq5tK0UsRg
		$a_01_2 = {6d 61 69 6e 2e 6d 61 6c 69 63 69 6f 75 73 } //1 main.malicious
		$a_01_3 = {6d 61 69 6e 2e 69 6e 66 65 63 74 42 69 6e 61 72 69 65 73 } //1 main.infectBinaries
		$a_01_4 = {6d 61 69 6e 2e 6e 6f 74 49 6e 66 65 63 74 42 69 6e } //1 main.notInfectBin
		$a_01_5 = {6d 61 69 6e 2e 78 6f 72 } //1 main.xor
		$a_01_6 = {6d 61 69 6e 2e 72 75 6e 48 6f 73 74 } //1 main.runHost
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}