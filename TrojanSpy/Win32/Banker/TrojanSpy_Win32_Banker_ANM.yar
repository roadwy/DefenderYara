
rule TrojanSpy_Win32_Banker_ANM{
	meta:
		description = "TrojanSpy:Win32/Banker.ANM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {27 30 30 31 31 30 20 31 30 30 30 31 20 30 31 30 30 31 20 31 31 30 30 30 20 30 30 31 30 31 20 31 30 31 30 30 20 30 31 31 30 30 20 30 30 30 31 31 20 31 30 30 31 30 20 30 31 30 31 30 27 } //1 '00110 10001 01001 11000 00101 10100 01100 00011 10010 01010'
		$a_01_1 = {27 43 4f 44 5f 42 41 52 4e 4f 53 53 4f 27 3b 76 61 72 20 61 3d 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 73 42 79 54 61 67 4e 61 6d 65 28 27 69 6d 67 27 29 } //1 'COD_BARNOSSO';var a=document.getElementsByTagName('img')
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 33 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 49 6e 64 79 20 4c 69 62 72 61 72 79 29 } //1 Mozilla/3.0 (compatible; Indy Library)
		$a_03_3 = {c1 e0 06 03 d8 89 ?? ?? 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b ?? ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b ?? ?? 99 f7 f9 } //1
		$a_00_4 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}