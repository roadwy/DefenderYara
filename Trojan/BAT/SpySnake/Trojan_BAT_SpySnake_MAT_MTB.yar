
rule Trojan_BAT_SpySnake_MAT_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 df b6 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 1d 01 00 00 a3 00 00 00 a5 } //1
		$a_01_1 = {48 69 64 65 43 6f 6e 73 6f 6c 65 } //1 HideConsole
		$a_01_2 = {43 6f 6e 73 6f 6c 65 4b 65 79 49 6e 66 6f } //1 ConsoleKeyInfo
		$a_01_3 = {74 72 65 65 50 6f 73 74 57 69 6e 64 6f 77 4d 6f 75 73 65 41 74 } //1 treePostWindowMouseAt
		$a_01_4 = {74 72 65 65 50 6f 73 74 57 69 6e 64 6f 77 5f 4b 65 79 55 70 } //1 treePostWindow_KeyUp
		$a_01_5 = {52 65 6c 65 61 73 65 43 61 70 74 75 72 65 } //1 ReleaseCapture
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}