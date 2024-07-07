
rule Trojan_Win32_Zloader_AD_MTB{
	meta:
		description = "Trojan:Win32/Zloader.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 83 f9 90 01 01 0f 82 90 01 04 81 f9 90 01 04 73 13 0f ba 25 90 01 04 01 0f 82 90 01 04 e9 90 01 04 0f ba 25 90 01 04 01 73 09 f3 a4 90 00 } //1
		$a_03_1 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 90 01 01 8b 44 24 04 f7 e1 c2 90 01 02 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 90 00 } //1
		$a_01_2 = {3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 :\Windows\iexplore.exe
		$a_03_3 = {5c 4c 65 61 73 74 5c 4f 72 69 67 69 6e 61 6c 5c 90 02 0a 5c 44 69 73 63 75 73 73 5c 4c 61 72 67 65 5c 90 01 02 5c 62 75 74 5c 46 69 74 2e 70 64 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}