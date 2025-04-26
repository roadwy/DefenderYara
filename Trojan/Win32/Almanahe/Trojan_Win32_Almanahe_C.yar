
rule Trojan_Win32_Almanahe_C{
	meta:
		description = "Trojan:Win32/Almanahe.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 50 89 75 e4 81 7d e4 d0 04 00 00 73 17 8b 45 e4 8d 80 ?? ?? ?? ?? 33 c9 8a 08 83 f1 23 88 08 ff 45 e4 eb e0 56 8d 45 e4 50 68 00 26 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Almanahe_C_2{
	meta:
		description = "Trojan:Win32/Almanahe.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7d e4 00 09 00 00 73 17 8b 45 e4 8d 80 ?? ?? ?? ?? 33 c9 8a 08 83 f1 3a 88 08 ff 45 e4 eb e0 } //1
		$a_01_1 = {5f 5f 44 4c 5f 43 4f 52 45 34 47 41 45 58 5f 4d 55 54 45 58 5f 5f 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Almanahe_C_3{
	meta:
		description = "Trojan:Win32/Almanahe.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {75 7c 33 c0 8a 88 ?? ?? ?? ?? 80 f1 66 88 8c 05 fc fe ff ff 40 3d c8 00 00 00 7c e8 } //5
		$a_01_1 = {44 4c 50 56 65 72 73 69 6f 6e 00 } //1
		$a_01_2 = {44 4c 50 54 65 72 6d 69 6e 61 74 65 00 } //1
		$a_01_3 = {44 4c 50 49 6e 69 74 00 } //1 䱄䥐楮t
		$a_01_4 = {5f 5f 44 4c 5f 43 4f 52 45 34 47 41 45 58 5f 4d 55 54 45 58 5f 5f 00 } //1
		$a_01_5 = {5f 5f 44 4c 34 47 41 45 58 5f 45 58 45 43 5f 5f 00 } //1
		$a_01_6 = {5f 5f 44 4c 34 47 41 45 58 5f 52 45 53 55 4c 54 5f 5f 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}