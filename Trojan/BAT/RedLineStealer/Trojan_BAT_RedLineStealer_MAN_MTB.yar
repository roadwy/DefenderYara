
rule Trojan_BAT_RedLineStealer_MAN_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-60] 2f 00 6d 00 69 00 63 00 72 00 69 00 66 00 69 00 65 00 73 00 2e 00 6a 00 70 00 67 00 } //1
		$a_02_1 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-60] 2f 6d 69 63 72 69 66 69 65 73 2e 6a 70 67 } //1
		$a_01_2 = {54 48 45 5f 49 4e 54 45 52 41 43 54 49 4f 4e } //1 THE_INTERACTION
		$a_01_3 = {53 55 50 45 52 5f 4c 4f 4b 45 52 } //1 SUPER_LOKER
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {50 69 63 74 75 72 65 20 50 75 7a 7a 6c 65 } //1 Picture Puzzle
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_8 = {4e 52 5f 44 65 74 72 6f 69 74 53 61 74 61 72 } //1 NR_DetroitSatar
		$a_01_9 = {67 65 74 5f 73 69 6e 66 6f 6e 69 65 74 74 61 73 } //1 get_sinfoniettas
		$a_00_10 = {e0 12 17 13 de 12 14 13 14 13 e7 12 e5 12 04 13 11 13 e0 12 f1 12 0f 13 16 13 e4 12 de 12 20 00 49 00 6e 00 63 00 2e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1) >=10
 
}