
rule PWS_Win32_Tibia_P{
	meta:
		description = "PWS:Win32/Tibia.P,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 77 6e 74 69 62 69 61 2e 63 6f 6d 2f 76 69 70 2f 64 6f 64 61 6a 2e 70 68 70 3f 6c 6f 67 69 6e 3d 25 73 26 6e 75 6d 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 6e 6f 74 61 74 6b 61 3d 25 73 26 73 65 72 77 65 72 3d 25 73 26 6c 76 6c 3d 25 64 26 6c 76 6c 70 3d 25 64 26 73 74 61 6d 3d 25 64 26 68 65 6c 6d 3d 25 64 26 6e 65 63 6b 3d 25 64 26 62 61 63 6b 3d 25 64 26 61 72 6d 3d 25 64 26 72 68 61 6e 64 3d 25 64 26 6c 68 61 6e 64 3d 25 64 26 6c 65 67 73 3d 25 64 26 66 65 65 74 3d 25 64 26 72 69 6e 67 3d 25 64 26 61 6d 6d 6f 3d 25 64 26 6e 63 68 61 72 3d 25 64 26 6c 68 61 6e 64 63 3d 25 64 26 72 68 61 6e 64 63 3d 25 64 26 61 6d 6d 6f 63 3d 25 64 } //1 owntibia.com/vip/dodaj.php?login=%s&numer=%s&pass=%s&notatka=%s&serwer=%s&lvl=%d&lvlp=%d&stam=%d&helm=%d&neck=%d&back=%d&arm=%d&rhand=%d&lhand=%d&legs=%d&feet=%d&ring=%d&ammo=%d&nchar=%d&lhandc=%d&rhandc=%d&ammoc=%d
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 Software\Microsoft\Windows\CurrentVersion\Run\
		$a_01_2 = {25 73 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 %s\system32\drivers\etc\hosts
		$a_01_3 = {31 32 37 2e 30 2e 30 2e 31 20 20 20 20 20 20 20 6c 6f 63 61 6c 68 6f 73 74 } //1 127.0.0.1       localhost
		$a_01_4 = {54 69 62 69 61 43 6c 69 65 6e 74 } //1 TibiaClient
		$a_01_5 = {70 72 6f 67 72 61 6d 66 69 6c 65 73 00 25 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 00 6c 73 61 73 73 2e 65 78 65 } //1 牰杯慲晭汩獥─屳湉整湲瑥䔠灸潬敲屲氀慳獳攮數
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}