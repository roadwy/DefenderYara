
rule Trojan_BAT_SpySnake_MY_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de } //2
		$a_01_1 = {57 46 41 5f 59 61 63 68 74 5f 44 69 63 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 WFA_Yacht_Dice.Properties
		$a_01_2 = {63 65 39 38 33 31 66 66 2d 33 64 38 35 2d 34 32 61 65 2d 39 65 33 38 2d 61 64 33 38 34 65 63 33 31 39 35 35 } //1 ce9831ff-3d85-42ae-9e38-ad384ec31955
		$a_01_3 = {74 69 6d 65 72 5f 72 65 63 65 69 76 65 4f 6e 6c 79 5f 54 69 63 6b } //1 timer_receiveOnly_Tick
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_SpySnake_MY_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {17 9a a2 25 18 72 ?? ?? ?? 70 a2 0c 02 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 25 16 16 8c ?? ?? ?? 01 a2 25 17 08 a2 25 13 05 14 14 18 8d ?? ?? ?? 01 25 17 17 9c 25 13 06 17 } //10
		$a_01_1 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 } //1 Control_Run
		$a_01_2 = {50 58 58 30 30 30 30 34 } //1 PXX00004
		$a_01_3 = {42 00 6f 00 6f 00 6b 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 } //1 BookInformation
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}