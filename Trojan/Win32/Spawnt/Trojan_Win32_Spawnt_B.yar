
rule Trojan_Win32_Spawnt_B{
	meta:
		description = "Trojan:Win32/Spawnt.B,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 54 65 73 74 } //1 :\Test
		$a_01_1 = {4f 6c 78 55 5a 58 4e 30 } //1 OlxUZXN0
		$a_01_2 = {3a 46 6c 69 6e 63 68 65 64 } //4 :Flinched
		$a_01_3 = {4f 6b 5a 73 61 57 35 6a 61 47 56 6b } //4 OkZsaW5jaGVk
		$a_02_4 = {6c 64 72 2e 65 78 65 90 09 02 00 6e 90 0a 16 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 } //6
		$a_03_5 = {6b c0 28 5d 01 c5 03 5d 0c 53 8d 6c 24 20 ff 75 00 (ff 15 ?? ?? ??|?? e8 ?? ??) ?? ?? ff 84 24 ?? ?? ?? ?? ?? ?? 68 00 00 00 00 68 04 00 00 00 } //5
		$a_03_6 = {81 fb 02 c4 97 70 75 3b e8 ?? ?? ?? ?? 50 50 } //5
		$a_03_7 = {83 fb 02 7c 1d 8b 1d ?? ?? ?? ?? 83 fb 06 7f 12 8b 1d ?? ?? ?? ?? 83 fb 05 74 07 b8 01 00 00 00 eb 02 31 c0 21 c0 74 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_02_4  & 1)*6+(#a_03_5  & 1)*5+(#a_03_6  & 1)*5+(#a_03_7  & 1)*10) >=26
 
}