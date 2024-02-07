
rule Spammer_Win32_Spawl_B{
	meta:
		description = "Spammer:Win32/Spawl.B,SIGNATURE_TYPE_PEHSTR,5b 00 5a 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 66 72 6f 6d 5f 6e 61 6d 65 25 00 25 73 75 62 6a 65 63 74 25 } //0a 00 
		$a_01_1 = {53 74 61 72 74 50 72 6f 63 65 73 73 41 74 57 69 6e 4c 6f 67 6f 6e } //0a 00  StartProcessAtWinLogon
		$a_01_2 = {41 73 79 6e 63 68 72 6f 6e 6f 75 73 } //0a 00  Asynchronous
		$a_01_3 = {53 74 6f 70 50 72 6f 63 65 73 73 41 74 57 69 6e 4c 6f 67 6f 66 66 } //0a 00  StopProcessAtWinLogoff
		$a_01_4 = {4e 6f 74 69 66 79 5c 00 57 69 6e 6c 6f 67 6f 6e 5c } //0a 00 
		$a_01_5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29 } //0a 00  Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
		$a_01_6 = {53 61 79 20 42 59 2d 42 59 } //0a 00  Say BY-BY
		$a_01_7 = {62 65 73 74 5f 73 65 61 72 63 68 00 70 61 74 68 20 3d } //0a 00  敢瑳獟慥捲h慰桴㴠
		$a_01_8 = {73 74 72 69 6b 65 62 61 63 6b } //01 00  strikeback
		$a_01_9 = {68 74 74 70 3a 2f 2f 67 61 61 67 6c 65 32 2e 63 6f 6d 2f } //01 00  http://gaagle2.com/
		$a_01_10 = {32 30 37 2e 32 32 36 2e 31 37 38 2e 31 35 38 } //01 00  207.226.178.158
		$a_01_11 = {32 30 36 2e 31 36 31 2e 32 30 35 2e 31 34 32 } //01 00  206.161.205.142
		$a_01_12 = {61 64 6d 69 6e 40 73 6d 74 70 2e 72 61 6d 62 6c 65 72 2e 72 75 } //01 00  admin@smtp.rambler.ru
		$a_01_13 = {61 64 6d 69 6e 40 73 6d 74 70 2e 79 61 6e 64 65 78 2e 72 75 } //00 00  admin@smtp.yandex.ru
	condition:
		any of ($a_*)
 
}