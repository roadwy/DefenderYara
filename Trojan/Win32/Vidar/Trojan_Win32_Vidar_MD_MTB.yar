
rule Trojan_Win32_Vidar_MD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f0 8b 45 f4 8b 4d f8 03 c7 d3 ef 89 45 e4 c7 05 90 01 08 03 7d d8 8b 45 e4 31 45 fc 33 7d fc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Vidar_MD_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b c6 8b f8 33 d2 8b c1 f7 f7 8b 45 0c 8d 34 19 41 8a 14 02 8b 85 ec fd ff ff 32 14 30 88 16 3b 8d f0 fd ff ff 72 } //10
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 57 } //1 GetLocaleInfoW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule Trojan_Win32_Vidar_MD_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 c8 76 d4 96 80 e2 15 69 87 ac da 47 b3 03 c6 54 69 11 ef 63 69 b9 ea 6c fb ce a6 fb dd 92 af 55 47 33 c6 26 e2 58 fc 5b bb ad d1 48 f0 98 e3 } //5
		$a_01_1 = {d0 21 fe a6 5d ea f4 64 16 eb ba 9b 19 0d ba c2 73 e1 c5 99 2e 4c c2 9c 13 39 93 b7 29 21 05 a4 36 ea 28 a3 2b eb d4 b1 19 f3 10 c1 1e 05 cd 64 } //5
		$a_01_2 = {e0 00 02 01 0b 01 50 00 00 b6 0f 00 00 54 03 00 00 00 00 00 e0 92 4e 00 00 20 } //2
		$a_01_3 = {e0 00 02 01 0b 01 50 00 00 32 10 00 00 20 01 00 00 00 00 00 b8 4d 4b 00 00 20 } //2
		$a_01_4 = {2e 74 68 65 6d 69 64 61 } //1 .themida
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}