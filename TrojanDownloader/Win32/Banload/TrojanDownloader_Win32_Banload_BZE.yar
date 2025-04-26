
rule TrojanDownloader_Win32_Banload_BZE{
	meta:
		description = "TrojanDownloader:Win32/Banload.BZE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 6f 72 74 75 67 75 ea 73 20 28 42 72 61 73 69 6c 29 00 } //1
		$a_01_1 = {76 68 72 79 74 68 79 34 64 66 68 00 } //1 桶祲桴㑹晤h
		$a_01_2 = {54 44 6f 77 6e 6c 6f 61 64 65 72 31 } //1 TDownloader1
		$a_01_3 = {53 61 6c 76 61 72 } //1 Salvar
		$a_01_4 = {41 32 38 39 41 36 34 36 45 31 } //1 A289A646E1
		$a_01_5 = {35 36 44 44 31 44 44 43 30 38 } //1 56DD1DDC08
		$a_01_6 = {59 55 51 4c 32 33 4b 4c 32 33 44 46 39 30 57 49 35 45 31 4a 41 53 34 36 37 4e 4d 43 58 58 4c 36 4a 41 4f 41 55 57 57 4d 43 4c 30 41 4f 4d 4d 34 41 34 56 5a 59 57 39 4b 48 4a 55 49 32 33 34 37 45 4a 48 4a 4b 44 46 33 34 32 34 } //1 YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM4A4VZYW9KHJUI2347EJHJKDF3424
		$a_01_7 = {0f 8e 4d 01 00 00 89 45 dc c7 45 e4 01 00 00 00 8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}