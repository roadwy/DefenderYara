
rule Trojan_BAT_Clipbanker_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {47 65 74 54 65 78 74 } //GetText  01 00 
		$a_80_1 = {53 65 74 54 65 78 74 } //SetText  01 00 
		$a_80_2 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  01 00 
		$a_80_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 56 69 65 77 65 72 } //SetClipboardViewer  01 00 
		$a_80_4 = {59 41 4e 44 45 58 5f 4d 4f 4e 45 59 } //YANDEX_MONEY  01 00 
		$a_80_5 = {53 54 45 41 4d 54 52 41 44 45 5f 4c 49 4e 4b } //STEAMTRADE_LINK  01 00 
		$a_80_6 = {45 54 48 45 52 45 55 4d } //ETHEREUM  01 00 
		$a_80_7 = {68 74 74 70 73 3a 2f 2f 73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d 2f 74 72 61 64 65 6f 66 66 65 72 2f 6e 65 77 2f 3f 70 61 72 74 6e 65 72 } //https://steamcommunity.com/tradeoffer/new/?partner  01 00 
		$a_80_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  01 00 
		$a_80_9 = {30 78 35 61 38 37 46 30 30 41 31 64 61 63 32 38 61 32 38 35 43 37 44 33 33 36 61 31 62 32 39 46 64 63 35 37 62 33 34 31 31 35 } //0x5a87F00A1dac28a285C7D336a1b29Fdc57b34115  01 00 
		$a_80_10 = {74 31 51 66 73 72 7a 73 63 4b 67 66 35 4b 69 61 62 55 63 41 4a 59 5a 62 54 63 6a 75 32 64 54 72 69 77 35 } //t1QfsrzscKgf5KiabUcAJYZbTcju2dTriw5  01 00 
		$a_01_11 = {5e 00 34 00 31 00 30 00 30 00 31 00 5b 00 30 00 2d 00 39 00 5d 00 3f 00 5b 00 5c 00 64 00 5c 00 2d 00 20 00 5d 00 7b 00 37 00 2c 00 31 00 31 00 7d 00 24 00 } //00 00  ^41001[0-9]?[\d\- ]{7,11}$
	condition:
		any of ($a_*)
 
}