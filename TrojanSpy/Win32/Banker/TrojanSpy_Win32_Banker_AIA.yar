
rule TrojanSpy_Win32_Banker_AIA{
	meta:
		description = "TrojanSpy:Win32/Banker.AIA,SIGNATURE_TYPE_PEHSTR_EXT,fffffffa 00 ffffffe6 00 07 00 00 "
		
	strings :
		$a_01_0 = {71 37 58 74 73 75 72 43 45 37 } //100 q7XtsurCE7
		$a_01_1 = {6d 37 6d 75 65 58 71 5a 62 66 6c 75 76 62 6e 4b 6d 54 6d 74 66 65 6e 63 31 63 6d 75 69 33 6c 74 71 37 6e 64 75 31 6d 5a 75 37 6d 64 61 } //50 m7mueXqZbfluvbnKmTmtfenc1cmui3ltq7ndu1mZu7mda
		$a_01_2 = {75 5a 6e 37 6e 63 6e 75 79 57 6c 74 75 58 72 4a 75 54 6e 64 6d 39 6e 73 31 62 6f 64 61 33 6c 74 76 67 71 74 71 39 72 74 6d 39 6f 74 61 } //50 uZn7ncnuyWltuXrJuTndm9ns1boda3ltvgqtq9rtm9ota
		$a_01_3 = {78 66 44 56 44 5a 79 37 6d 5a 6a 6f 42 38 72 4c 78 } //30 xfDVDZy7mZjoB8rLx
		$a_01_4 = {78 65 44 49 41 77 76 4f 75 38 6e 4b 6c 4b 44 49 73 77 76 4f 74 38 6a 51 } //30 xeDIAwvOu8nKlKDIswvOt8jQ
		$a_01_5 = {78 68 6e 39 43 32 72 4c 42 74 6d 59 78 67 44 49 43 67 54 54 6c 4e 6e 39 43 57 } //20 xhn9C2rLBtmYxgDICgTTlNn9CW
		$a_01_6 = {44 38 4c 55 7a 67 4c 59 } //20 D8LUzgLY
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*30+(#a_01_4  & 1)*30+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20) >=230
 
}