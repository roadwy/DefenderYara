
rule Trojan_Win32_RedLine_MBEE_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 31 4a 58 38 63 78 63 53 37 7a 62 6c 34 6a 6a 77 55 41 62 4a 46 6a 48 71 41 43 44 6d 74 } //1 K1JX8cxcS7zbl4jjwUAbJFjHqACDmt
		$a_01_1 = {6e 6c 61 68 4a 59 6c 61 77 55 5a 69 66 79 54 70 4f 6e 77 50 6e 75 4d 46 58 46 65 5a 63 53 53 4e 57 59 } //1 nlahJYlawUZifyTpOnwPnuMFXFeZcSSNWY
		$a_01_2 = {71 49 62 55 79 41 5a 58 73 75 73 79 63 4b 57 48 65 44 64 4f } //1 qIbUyAZXsusycKWHeDdO
		$a_01_3 = {71 72 4a 75 61 5a 42 62 58 4d 41 41 7a 55 4f 6f 6a 46 5a 7a 57 50 76 52 53 66 46 47 77 77 7a 78 6d 67 } //1 qrJuaZBbXMAAzUOojFZzWPvRSfFGwwzxmg
		$a_01_4 = {37 69 47 6b 46 42 41 52 35 63 63 31 33 34 4d 32 72 64 5a 6a 37 6f 42 66 75 72 6f 7a 76 44 62 } //1 7iGkFBAR5cc134M2rdZj7oBfurozvDb
		$a_01_5 = {48 59 52 55 4d 4e 46 75 38 39 65 5a 35 68 68 58 57 } //1 HYRUMNFu89eZ5hhXW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}