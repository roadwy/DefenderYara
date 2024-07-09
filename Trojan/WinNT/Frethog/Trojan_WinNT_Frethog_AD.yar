
rule Trojan_WinNT_Frethog_AD{
	meta:
		description = "Trojan:WinNT/Frethog.AD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 40 04 89 45 ?? 81 e9 4b e1 22 00 [0-07] 83 e9 ?? 74 0a ?? bb 00 00 c0 e9 } //2
		$a_01_1 = {80 4e 06 01 6a 00 56 ff 15 } //1
		$a_03_2 = {83 65 fc 00 6a 04 6a 04 57 ff 15 ?? ?? 01 00 6a 04 6a 04 ?? ff 15 ?? ?? 01 00 83 4d fc ff 8b } //3
		$a_03_3 = {83 e8 05 89 45 ?? 6a 05 ?? 8d 45 90 09 03 00 e9 } //3
		$a_01_4 = {83 fe 01 74 1d 83 fe 02 74 18 83 fe 26 74 13 83 fe 03 74 0e 83 fe 25 74 09 83 fe 0c } //2
		$a_01_5 = {3b 7d 1c 75 09 c7 45 28 06 00 00 80 eb 0b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=9
 
}