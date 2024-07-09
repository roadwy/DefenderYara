
rule Ransom_Win32_Gulcrypt_A{
	meta:
		description = "Ransom:Win32/Gulcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2a 2e 43 68 69 70 44 61 6c 65 } //1 *.ChipDale
		$a_01_1 = {50 49 4e 47 20 2d 6e 20 35 20 2d 77 20 31 30 30 30 20 31 32 37 2e 30 2e 30 2e 31 20 3e 20 6e 75 6c } //1 PING -n 5 -w 1000 127.0.0.1 > nul
		$a_01_2 = {64 65 6c 20 73 79 73 74 65 6d 54 72 61 79 57 2e 65 78 65 } //1 del systemTrayW.exe
		$a_01_3 = {00 63 68 69 70 5f 61 6e 64 5f 64 61 6c 65 2e 76 7a 68 6b 00 } //1 挀楨彰湡彤慤敬瘮桺k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Gulcrypt_A_2{
	meta:
		description = "Ransom:Win32/Gulcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {0a ed e0 e6 ec e8 f2 e5 20 ea ed ee ef ea f3 20 43 72 65 61 74 65 20 72 61 6e 64 6f 6d 20 61 64 64 72 65 73 73 2e 20 c2 f1 e5 2c 20 e2 fb 20 ec } //1
		$a_01_1 = {ea ed ee ef ea f3 20 53 65 6e 64 20 4d 65 73 73 61 67 65 0d 0a 28 ef ee f1 eb e0 f2 fc 20 f1 ee } //1
		$a_03_2 = {21 21 d4 e0 e9 eb fb 20 e7 e0 f8 e8 f4 f0 ee e2 e0 ed fb [0-05] 2e 74 78 74 00 } //5
		$a_03_3 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d ?? ?? 40 00 80 e9 41 c7 05 ?? ?? 40 00 3a 5c 2a 2e c6 05 ?? ?? 40 00 2a c6 05 ?? ?? 40 00 00 50 51 e8 ?? ?? ff ff 59 58 49 7d c5 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5) >=6
 
}