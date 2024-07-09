
rule Trojan_BAT_SpySnake_MH_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 09 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 9c 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_SpySnake_MH_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 5b 8d 31 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4 } //5
		$a_01_1 = {3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 32 00 31 00 36 00 2e 00 37 00 31 00 2e 00 31 00 32 00 30 00 2f 00 } //5 ://185.216.71.120/
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {52 6f 6f 6c 6c } //1 Rooll
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_BAT_SpySnake_MH_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_2 = {44 54 54 2e 65 78 65 } //1 DTT.exe
		$a_81_3 = {47 61 6d 65 57 69 6e 64 6f 77 } //1 GameWindow
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {4f 74 68 65 6c 6c 6f 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e } //1 OthelloWindowsApplication
		$a_03_6 = {19 8d 0a 00 00 01 25 16 72 17 00 00 70 a2 25 17 72 5d 00 00 70 a2 25 18 07 06 28 ?? ?? ?? 06 a2 0c 20 05 00 00 00 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}