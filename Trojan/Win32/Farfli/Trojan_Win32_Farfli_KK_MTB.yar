
rule Trojan_Win32_Farfli_KK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 85 30 fe ff ff 50 ff d7 8d 85 30 fe ff ff 50 ff d3 6a 00 6a 00 6a 00 8d 85 30 fe ff ff 50 ff d6 85 c0 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}
rule Trojan_Win32_Farfli_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 b9 1a 00 00 00 f7 f9 46 3b f7 8a 54 14 10 88 54 1e ff } //20
		$a_01_1 = {65 6b 69 6d 68 75 71 63 72 6f 61 6e 66 6c 76 7a 67 64 6a 74 78 79 70 73 77 62 } //10 ekimhuqcroanflvzgdjtxypswb
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Farfli_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 46 14 89 5e 20 89 5e 18 89 5e 1c ?? ?? ?? ?? 89 46 24 89 5e 30 89 5e 28 89 5e 2c ?? ?? ?? ?? 89 46 34 89 5e 40 89 5e 38 89 5e 3c } //20
		$a_01_1 = {80 34 38 a7 40 3b c6 } //10
		$a_01_2 = {66 6e 74 31 31 32 32 74 64 6c 6c } //5 fnt1122tdll
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win32_Farfli_KK_MTB_4{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 7e 44 89 7e 48 89 7e 54 89 7e 58 89 7e 5c 89 7e 60 c7 46 64 03 00 00 00 } //20
		$a_01_1 = {6a 00 68 18 01 00 00 8d 85 e8 fc ff ff 50 53 56 ff } //15
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 51 65 69 79 53 42 63 61 70 56 2e 64 61 74 } //10 C:\Users\Public\Documents\QeiySBcapV.dat
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 57 69 6e 64 6f 77 73 44 61 74 61 5c 6b 61 69 6c 2e 65 78 65 } //5 C:\Users\Public\Documents\WindowsData\kail.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=50
 
}