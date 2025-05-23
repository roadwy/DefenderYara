
rule Trojan_Win32_Tinba_F{
	meta:
		description = "Trojan:Win32/Tinba.F,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {f3 a4 29 fe 80 7f fb e8 (|74 06 80 7f fb e9) 75 03 01 77 fc 83 ee 05 c6 07 e9 89 77 01 8b 7d 0c 89 07 8b 7d ?? 8b 45 08 29 f8 83 e8 05 c6 07 e9 89 47 01 50 8d 45 ?? 87 04 24 ff 75 ?? 6a 20 ff 75 ?? ff 93 } //2
		$a_03_1 = {01 c1 01 c6 83 fe 05 72 ee 87 ce 89 f8 29 ce f3 a4 29 fe 83 ee 05 c6 07 e9 89 77 01 8b 7d 0c 89 07 8b 7d ?? 8b 45 08 29 f8 83 e8 05 c6 07 e9 89 47 01 8d 55 ?? 52 ff 75 ?? 6a 20 ff 75 ?? ff 93 } //2
		$a_01_2 = {03 52 3c 8b 52 78 01 c2 8b 72 20 01 c6 31 c9 41 83 c6 04 8b 3e 01 c7 81 7f 05 6f 63 41 64 75 ef } //2
		$a_03_3 = {00 4e 74 43 72 65 61 74 65 55 73 65 72 50 72 6f 63 65 73 73 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 45 78 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 43 72 65 61 74 65 54 68 72 65 61 64 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 45 6e 75 6d 65 72 61 74 65 56 61 6c 75 65 4b 65 79 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 00 ?? ?? ?? ?? ?? ?? ?? 00 52 74 6c 43 72 65 61 74 65 55 73 65 72 54 68 72 65 61 64 00 } //2
		$a_03_4 = {87 04 24 6a 40 68 eb 00 00 00 ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff 93 } //1
		$a_03_5 = {04 2f 0f 85 ?? ?? ?? ?? 6a 04 e8 90 09 0e 00 81 ?? 48 54 54 50 0f 85 ?? ?? ?? ?? 80 } //1
		$a_03_6 = {81 3e 47 45 54 20 74 17 81 3e 50 4f 53 54 0f 85 ?? ?? ?? ?? 80 7e 04 20 0f 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}