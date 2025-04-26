
rule Trojan_BAT_Beyuwa_A{
	meta:
		description = "Trojan:BAT/Beyuwa.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 31 00 6b 32 00 6b 33 } //1 ㅫ欀2㍫
		$a_01_1 = {42 79 65 00 52 75 6e 41 77 61 79 00 57 68 79 } //1
		$a_01_2 = {62 31 00 62 32 00 62 33 } //1 ㅢ戀2㍢
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Beyuwa_A_2{
	meta:
		description = "Trojan:BAT/Beyuwa.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6e 6b 56 69 65 77 65 72 } //1 LinkViewer
		$a_01_1 = {53 74 61 72 74 55 70 } //1 StartUp
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 4c 69 73 74 } //1 DownloadList
		$a_01_3 = {53 68 75 66 66 6c 65 } //1 Shuffle
		$a_01_4 = {44 69 73 61 62 6c 65 43 6c 69 63 6b 53 6f 75 6e 64 73 } //1 DisableClickSounds
		$a_01_5 = {2f 00 6e 00 69 00 67 00 2e 00 74 00 78 00 74 00 } //1 /nig.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_Beyuwa_A_3{
	meta:
		description = "Trojan:BAT/Beyuwa.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 78 01 00 70 a2 09 17 72 86 01 00 70 a2 09 18 72 8a 01 00 70 a2 09 17 6f } //2
		$a_01_1 = {8e 69 2d 02 16 2a 02 02 02 7b } //2
		$a_01_2 = {2f 00 6e 00 69 00 67 00 2e 00 74 00 78 00 74 00 } //2 /nig.txt
		$a_01_3 = {38 00 30 00 2e 00 32 00 34 00 32 00 2e 00 31 00 32 00 33 00 2e 00 32 00 31 00 31 00 3a 00 38 00 38 00 38 00 } //2 80.242.123.211:888
		$a_01_4 = {2f 00 72 00 65 00 66 00 65 00 72 00 2e 00 74 00 78 00 74 00 } //1 /refer.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=5
 
}