
rule Trojan_BAT_SpySnake_MA_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5 06 17 58 0a 00 09 17 58 0d 09 20 00 d0 00 00 fe 04 13 06 11 06 2d a8 } //10
		$a_01_1 = {66 69 72 73 74 43 6c 69 63 6b 65 64 } //1 firstClicked
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {54 69 6d 65 72 31 5f 54 69 63 6b } //1 Timer1_Tick
		$a_01_4 = {4d 6f 76 65 6d 65 6e 74 54 6f 44 6f 77 6e } //1 MovementToDown
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
rule Trojan_BAT_SpySnake_MA_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 42 79 74 65 73 } //GetBytes  1
		$a_80_1 = {52 65 70 6c 61 63 65 } //Replace  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  1
		$a_80_4 = {43 6f 6e 63 61 74 } //Concat  1
		$a_80_5 = {47 65 74 53 74 72 69 6e 67 } //GetString  1
		$a_03_6 = {0d 09 07 6f ?? ?? ?? 0a 17 90 0a 1a 00 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 28 00 00 0a [0-0d] 73 2a 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a de 0c } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_03_6  & 1)*10) >=16
 
}
rule Trojan_BAT_SpySnake_MA_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 15 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 81 00 00 00 0b 00 00 00 7a 00 00 00 4b 00 00 00 48 00 00 00 ce } //5
		$a_01_1 = {47 61 6d 65 5f 6f 66 5f 50 69 67 2e 50 72 6f 70 65 72 74 69 65 73 } //5 Game_of_Pig.Properties
		$a_01_2 = {46 49 55 53 48 55 49 46 } //5 FIUSHUIF
		$a_01_3 = {34 65 37 66 62 62 34 33 2d 64 32 61 65 2d 34 35 36 61 2d 61 64 37 37 2d 34 66 36 38 61 62 61 31 30 31 30 37 } //5 4e7fbb43-d2ae-456a-ad77-4f68aba10107
		$a_01_4 = {72 6f 6c 6c 42 75 74 74 6f 6e 5f 43 6c 69 63 6b } //1 rollButton_Click
		$a_01_5 = {45 6e 74 65 72 5f 44 65 74 61 69 6c 73 } //1 Enter_Details
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=22
 
}