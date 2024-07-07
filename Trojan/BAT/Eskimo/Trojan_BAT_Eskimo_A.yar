
rule Trojan_BAT_Eskimo_A{
	meta:
		description = "Trojan:BAT/Eskimo.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_80_0 = {37 36 35 36 31 31 39 5b 30 2d 39 5d 7b 31 30 7d 25 37 63 25 37 63 5b 41 2d 46 30 2d 39 5d 7b 34 30 7d } //7656119[0-9]{10}%7c%7c[A-F0-9]{40}  6
		$a_01_1 = {18 04 3d 04 38 04 46 04 38 04 30 04 3b 04 38 04 37 04 30 04 46 04 38 04 4f 04 20 00 44 04 30 04 39 04 3b 04 3e 04 32 04 2e 00 2e 00 2e 00 } //1 Инициализация файлов...
		$a_80_2 = {74 72 61 64 65 6f 66 66 65 72 2f 6e 65 77 2f 3f 70 61 72 74 6e 65 72 3d } //tradeoffer/new/?partner=  1
		$a_80_3 = {63 6f 6d 6d 6f 6e 2c 75 6e 63 6f 6d 6d 6f 6e 2c 72 61 72 65 2c 6d 79 74 68 69 63 61 6c 2c 6c 65 67 65 6e 64 61 72 79 2c 69 6d 6d 6f 72 74 61 6c } //common,uncommon,rare,mythical,legendary,immortal  1
		$a_80_4 = {73 74 65 61 6d 4c 6f 67 69 6e } //steamLogin  1
		$a_80_5 = {73 74 65 61 6d 63 6c 69 65 6e 74 2e 64 6c 6c } //steamclient.dll  1
		$a_80_6 = {53 74 65 61 6d 53 74 65 61 6c } //SteamSteal  5
	condition:
		((#a_80_0  & 1)*6+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*5) >=8
 
}