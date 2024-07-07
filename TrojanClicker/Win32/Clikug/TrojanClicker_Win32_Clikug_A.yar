
rule TrojanClicker_Win32_Clikug_A{
	meta:
		description = "TrojanClicker:Win32/Clikug.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 47 43 5f 43 6f 6e 74 72 6f 6c 6c 65 72 00 } //2
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 47 69 67 61 43 6c 69 63 6b 73 20 43 72 61 77 6c 65 72 } //2 SOFTWARE\GigaClicks Crawler
		$a_01_2 = {43 68 72 6f 6d 65 20 57 6f 72 6b 65 72 20 46 61 69 6c 65 64 2c 20 25 73 } //1 Chrome Worker Failed, %s
		$a_01_3 = {43 6c 69 63 6b 20 54 6f 20 78 3a 20 25 64 20 79 3a 20 25 64 } //1 Click To x: %d y: %d
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule TrojanClicker_Win32_Clikug_A_2{
	meta:
		description = "TrojanClicker:Win32/Clikug.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 00 69 00 67 00 61 00 43 00 6c 00 69 00 63 00 6b 00 73 00 20 00 43 00 72 00 61 00 77 00 6c 00 65 00 72 00 } //2 GigaClicks Crawler
		$a_01_1 = {43 68 72 6f 6d 65 20 57 6f 72 6b 65 72 20 46 61 69 6c 65 64 2c 20 25 73 } //1 Chrome Worker Failed, %s
		$a_01_2 = {43 6c 69 63 6b 20 54 6f 20 78 3a 20 25 64 20 79 3a 20 25 64 } //2 Click To x: %d y: %d
		$a_01_3 = {25 73 2f 73 74 61 74 2f 75 69 64 2f 25 73 2f 73 69 64 2f 25 64 2f 61 2f 25 73 2f } //2 %s/stat/uid/%s/sid/%d/a/%s/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=7
 
}