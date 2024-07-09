
rule Trojan_Win32_Coopop_B{
	meta:
		description = "Trojan:Win32/Coopop.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 49 45 4e 41 4d 45 00 00 53 45 54 00 49 53 4c 41 58 43 48 45 43 4b 00 00 49 45 2e 69 6e 69 00 } //1 䤀久䵁E匀呅䤀䱓塁䡃䍅K䤀⹅湩i
		$a_01_1 = {8a 04 11 f6 d0 88 04 11 8b c1 49 85 c0 7f f1 } //1
		$a_03_2 = {68 1f 00 02 00 53 68 48 c1 00 10 68 01 00 00 80 89 ?? ?? 18 89 ?? ?? 24 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Coopop_B_2{
	meta:
		description = "Trojan:Win32/Coopop.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 31 6a c5 00 68 40 1f 00 00 89 86 14 03 00 00 89 86 20 03 00 00 89 86 18 03 00 00 8d 44 24 24 8d be b8 00 00 00 56 50 68 52 00 00 50 } //2
		$a_00_1 = {61 64 75 6e 69 6f 6e 2f 72 65 70 6f 72 74 6d 61 63 2e 61 73 70 3f 6d 61 63 3d 25 73 26 69 69 70 3d 25 73 26 62 69 61 6e 6d 61 3d 25 73 26 76 65 72 3d 69 65 } //2 adunion/reportmac.asp?mac=%s&iip=%s&bianma=%s&ver=ie
		$a_00_2 = {75 6e 2e 35 38 77 62 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 } //1 un.58wb.com/search.asp
		$a_00_3 = {54 41 4f 4b 45 49 44 } //1 TAOKEID
		$a_00_4 = {59 4f 55 44 41 4f 49 44 } //1 YOUDAOID
		$a_00_5 = {53 4f 47 4f 55 49 44 } //1 SOGOUID
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}