
rule Trojan_BAT_SpySnake_MZ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 02 16 02 8e 69 6f 77 00 00 0a 0c 08 0d de 0b 07 2c 07 07 6f 90 01 03 0a 00 dc 09 2a 90 00 } //5
		$a_01_1 = {44 36 6e 67 65 72 6f 75 73 } //1 D6ngerous
		$a_01_2 = {41 64 6a 75 73 74 6d 34 6e 74 } //1 Adjustm4nt
		$a_01_3 = {53 6f 6d 35 74 69 6d 35 73 } //1 Som5tim5s
		$a_01_4 = {47 72 6f 77 69 31 67 } //1 Growi1g
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
rule Trojan_BAT_SpySnake_MZ_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 17 b6 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6a 00 00 00 37 00 00 00 08 01 } //10
		$a_01_1 = {31 36 30 30 34 37 63 33 2d 32 63 32 30 2d 34 34 65 30 2d 39 61 61 66 2d 39 66 30 37 32 65 64 32 62 33 33 33 } //5 160047c3-2c20-44e0-9aaf-9f072ed2b333
		$a_01_2 = {4a 61 6d 62 6f } //5 Jambo
		$a_01_3 = {42 4c 4c 5f 44 41 4c 2e 50 72 6f 70 65 72 74 69 65 73 } //5 BLL_DAL.Properties
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_7 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=29
 
}
rule Trojan_BAT_SpySnake_MZ_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0b 07 0c 2b 00 08 2a 90 0a 3f 00 7e 90 01 03 04 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 7e 90 01 03 04 06 6f 90 01 03 0a 00 7e 90 01 03 04 18 6f 90 01 03 0a 00 02 28 90 01 03 06 90 00 } //1
		$a_01_1 = {4d 69 72 61 72 6d 61 72 } //1 Mirarmar
		$a_01_2 = {47 65 74 48 6f 73 74 45 6e 74 72 79 } //1 GetHostEntry
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {52 65 74 72 69 65 76 65 44 61 74 61 } //1 RetrieveData
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}