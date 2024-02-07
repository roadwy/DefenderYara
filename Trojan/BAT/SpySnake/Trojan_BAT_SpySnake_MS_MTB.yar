
rule Trojan_BAT_SpySnake_MS_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {17 13 1e 20 e6 8e fb 0e 13 1f 11 1f 20 ed 8e fb 0e fe 02 13 5e 11 5e 2c 09 20 f8 8e fb 0e 13 1f 2b 1d 11 1f 20 1e 8f fb 0e fe 02 16 fe 01 13 5f 11 5f 2c 08 } //0a 00 
		$a_03_1 = {57 95 a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 74 00 00 00 16 00 00 00 51 00 00 00 90 01 01 01 00 00 90 01 01 00 00 00 cd 00 00 00 28 00 00 00 07 00 00 00 90 01 01 00 00 00 04 00 00 00 09 00 00 00 10 00 00 00 04 90 00 } //0a 00 
		$a_01_2 = {34 32 38 31 62 32 30 38 2d 33 39 61 35 2d 34 63 63 34 2d 62 35 32 34 2d 36 65 39 61 66 36 32 36 66 36 32 31 } //0a 00  4281b208-39a5-4cc4-b524-6e9af626f621
		$a_01_3 = {4d 61 6c 61 67 61 5f 67 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 } //05 00  Malaga_game.Properties
		$a_01_4 = {53 65 6c 66 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e } //00 00  Self installation
	condition:
		any of ($a_*)
 
}