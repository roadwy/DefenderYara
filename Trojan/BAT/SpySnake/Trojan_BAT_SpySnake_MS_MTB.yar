
rule Trojan_BAT_SpySnake_MS_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 1f a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 72 00 00 00 6c 00 00 00 10 01 00 00 2c 02 00 00 82 01 00 00 02 00 00 00 86 } //10
		$a_01_1 = {59 75 43 68 61 6e 67 2e 43 6f 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } //5 YuChang.Core.Properties
		$a_01_2 = {51 52 5f 53 43 45 4e 45 } //1 QR_SCENE
		$a_01_3 = {70 6f 73 74 44 61 74 61 } //1 postData
		$a_01_4 = {67 65 74 5f 4e 65 78 74 4f 70 65 6e 49 64 } //1 get_NextOpenId
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}
rule Trojan_BAT_SpySnake_MS_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {17 13 1e 20 e6 8e fb 0e 13 1f 11 1f 20 ed 8e fb 0e fe 02 13 5e 11 5e 2c 09 20 f8 8e fb 0e 13 1f 2b 1d 11 1f 20 1e 8f fb 0e fe 02 16 fe 01 13 5f 11 5f 2c 08 } //10
		$a_03_1 = {57 95 a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 74 00 00 00 16 00 00 00 51 00 00 00 90 01 01 01 00 00 90 01 01 00 00 00 cd 00 00 00 28 00 00 00 07 00 00 00 90 01 01 00 00 00 04 00 00 00 09 00 00 00 10 00 00 00 04 90 00 } //10
		$a_01_2 = {34 32 38 31 62 32 30 38 2d 33 39 61 35 2d 34 63 63 34 2d 62 35 32 34 2d 36 65 39 61 66 36 32 36 66 36 32 31 } //10 4281b208-39a5-4cc4-b524-6e9af626f621
		$a_01_3 = {4d 61 6c 61 67 61 5f 67 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 } //10 Malaga_game.Properties
		$a_01_4 = {53 65 6c 66 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e } //5 Self installation
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5) >=35
 
}