
rule Trojan_BAT_SpySnake_MQ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 3f b6 1d 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9b 00 00 00 13 00 00 00 7c 00 00 00 90 00 00 00 9a } //10
		$a_01_1 = {31 63 37 63 36 61 34 65 2d 62 31 36 61 2d 34 65 64 34 2d 38 38 31 33 2d 35 61 61 33 30 65 39 65 66 63 36 39 } //5 1c7c6a4e-b16a-4ed4-8813-5aa30e9efc69
		$a_01_2 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_3 = {77 65 62 42 72 6f 77 73 65 72 5f 4e 61 76 69 67 61 74 65 43 6f 6d 70 6c 65 74 65 } //1 webBrowser_NavigateComplete
		$a_01_4 = {50 61 73 73 55 72 6c 54 6f 42 72 6f 6b 65 72 } //1 PassUrlToBroker
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}
rule Trojan_BAT_SpySnake_MQ_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 62 d1 43 42 32 68 69 68 64 68 6f 90 9b 18 38 f9 43 41 32 68 69 6c 64 28 6f 6f 64 18 38 41 43 41 32 68 69 } //5
		$a_81_1 = {d0 98 d0 b8 d1 81 d1 83 d1 81 50 37 72 63 37 6e 74 61 67 37 2e 50 72 6f 70 65 72 74 69 65 73 } //5
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {67 65 74 5f 41 63 63 65 73 73 5f 74 6f 6b 65 6e } //1 get_Access_token
		$a_01_4 = {45 78 63 65 70 74 69 6f 6e 4c 6f 67 67 65 72 } //1 ExceptionLogger
		$a_01_5 = {67 65 74 5f 44 61 74 61 44 69 73 6b 49 6d 61 67 65 73 } //1 get_DataDiskImages
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}
rule Trojan_BAT_SpySnake_MQ_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4f 49 55 54 45 52 53 57 42 41 4a 48 47 46 46 } //1 OIUTERSWBAJHGFF
		$a_01_1 = {50 4c 4f 4b 4e 4d 4a 49 55 48 42 56 47 59 54 46 43 } //1 PLOKNMJIUHBVGYTFC
		$a_01_2 = {4d 44 49 50 50 31 5a } //1 MDIPP1Z
		$a_01_3 = {6e 75 6d 65 72 69 63 55 70 44 6f 77 6e 31 5f 56 61 6c 75 65 43 68 61 6e 67 65 64 } //1 numericUpDown1_ValueChanged
		$a_01_4 = {4d 44 49 50 50 31 } //1 MDIPP1
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {44 65 61 6c 44 61 6d 61 67 65 } //1 DealDamage
		$a_01_7 = {4e 75 6d 65 72 69 63 55 70 44 6f 77 6e } //1 NumericUpDown
		$a_01_8 = {67 65 74 5f 4b 69 6c 6c 43 6f 75 6e 74 } //1 get_KillCount
		$a_01_9 = {39 63 35 34 62 31 39 30 2d 65 35 63 61 2d 34 62 34 32 2d 38 66 62 63 2d 32 65 30 66 38 61 31 36 33 66 63 63 } //1 9c54b190-e5ca-4b42-8fbc-2e0f8a163fcc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}