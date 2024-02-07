
rule Trojan_BAT_SpySnake_MT_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 16 0d 2b 16 06 09 28 90 01 03 06 13 04 07 09 11 04 6f 90 01 03 0a 09 18 58 0d 09 06 6f 90 01 03 0a 32 e1 90 00 } //01 00 
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MT_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 90 01 03 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de 90 00 } //01 00 
		$a_01_1 = {47 61 6d 65 46 6f 72 6d 5f 4b 65 79 44 6f 77 6e } //01 00  GameForm_KeyDown
		$a_01_2 = {65 30 37 63 64 61 37 32 2d 37 31 62 33 2d 34 32 39 35 2d 38 36 35 37 2d 64 37 61 61 31 62 33 62 35 62 31 33 } //00 00  e07cda72-71b3-4295-8657-d7aa1b3b5b13
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MT_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 6f 90 01 03 0a 72 90 01 01 00 00 70 28 90 01 03 0a 13 06 11 06 2c 4d 00 11 05 6f 90 01 03 0a 13 07 16 13 08 2b 36 11 07 11 08 9a 13 09 11 09 6f 90 01 03 0a 72 90 01 01 01 00 70 28 90 01 03 0a 13 0a 11 0a 2c 12 11 09 14 14 6f 90 01 03 0a a5 90 01 01 00 00 01 13 0b 2b 2d 11 08 17 58 13 08 11 08 11 07 8e 69 32 c2 90 00 } //01 00 
		$a_01_1 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 } //01 00  CurrentDomain
		$a_01_2 = {51 75 65 75 65 55 73 65 72 57 6f 72 6b 49 74 65 6d } //01 00  QueueUserWorkItem
		$a_01_3 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 62 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 } //01 00  /c ping bing.com
		$a_01_4 = {46 72 6f 6d 53 65 63 6f 6e 64 73 } //01 00  FromSeconds
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {52 00 65 00 76 00 65 00 72 00 73 00 65 00 } //01 00  Reverse
		$a_03_7 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 90 02 60 2e 00 6a 00 70 00 67 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}