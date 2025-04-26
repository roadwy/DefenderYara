
rule Trojan_Win32_IRCBot_RT_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 c1 13 5d 5b 45 09 c9 e8 ?? ?? ?? ?? 29 db 43 b9 65 5b 3f 9c 31 10 21 cb 81 e9 c0 50 6b a8 41 81 c0 02 00 00 00 b9 65 1e 88 e2 39 f0 7c } //1
		$a_03_1 = {81 c2 04 4e df 72 e8 ?? ?? ?? ?? 29 d2 31 1f 81 e8 2d 95 16 35 09 d2 01 d0 81 c7 02 00 00 00 89 c2 81 e8 37 95 a6 ef 39 cf 7c } //1
		$a_03_2 = {81 eb 78 a9 ba c6 e8 ?? ?? ?? ?? 4a 31 07 81 ea 98 d7 0c f8 21 d3 09 d2 81 c7 02 00 00 00 89 da 39 cf 7c } //1
		$a_03_3 = {bf cc 46 47 00 48 e8 ?? ?? ?? ?? b8 83 5e ce f9 01 db 31 39 29 d8 21 c3 81 c1 02 00 00 00 09 c3 39 f1 7c } //1
		$a_03_4 = {81 c0 78 16 2b 7c e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 31 17 89 d8 21 c0 29 db 81 c7 02 00 00 00 81 c0 37 be 54 81 68 d7 19 e4 24 58 39 cf 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}
rule Trojan_Win32_IRCBot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/IRCBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 09 00 00 "
		
	strings :
		$a_02_0 = {bb da cc 43 00 e8 ?? ?? ?? ?? 89 c8 31 1e 81 e9 44 5d ee 23 40 46 39 d6 75 } //1
		$a_02_1 = {bb 2e ce 43 00 56 5a e8 ?? ?? ?? ?? 29 d6 31 1f 09 f6 42 47 68 3b 11 ed 46 5a 81 ee e2 d9 f4 49 39 cf 75 } //1
		$a_02_2 = {b9 2e ce 43 00 81 c7 bf c1 f4 cf e8 ?? ?? ?? ?? 81 ea 01 00 00 00 31 08 4f 40 47 39 f0 75 } //1
		$a_02_3 = {bf 2e ce 43 00 21 f1 e8 ?? ?? ?? ?? 29 ce 31 3b 83 ec 04 89 34 24 8b 34 24 83 c4 04 43 01 f6 81 ee 0e 4f b1 9a 39 c3 75 } //1
		$a_02_4 = {b8 2e ce 43 00 81 ef 91 ae b6 24 01 fb e8 ?? ?? ?? ?? 09 db 81 c7 01 00 00 00 31 01 81 c1 01 00 00 00 47 81 c7 01 00 00 00 39 d1 75 } //1
		$a_02_5 = {be 2e ce 43 00 e8 ?? ?? ?? ?? b8 c7 48 8f db 31 31 41 39 f9 75 } //1
		$a_02_6 = {68 2e ce 43 00 59 e8 ?? ?? ?? ?? 01 fb 29 df 31 0a 89 db 89 df 42 39 c2 75 e6 } //1
		$a_02_7 = {b8 ec 09 71 00 81 c6 07 34 70 c6 e8 ?? ?? ?? ?? 01 f2 31 07 46 be ea d4 4a 61 47 4e 39 df 75 } //1
		$a_02_8 = {ba ec 09 71 00 81 c1 57 a3 16 93 29 ff e8 ?? ?? ?? ?? 01 f9 b9 f6 f9 5d 49 31 16 29 cf 81 c6 01 00 00 00 81 c7 43 37 47 17 01 ff 39 c6 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1) >=1
 
}
rule Trojan_Win32_IRCBot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/IRCBot.RT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 ec 09 71 00 8b 04 24 83 c4 04 01 f6 89 f1 01 ce e8 1e 00 00 00 81 ee 14 66 46 34 31 02 29 ce 21 f6 01 f6 } //1
		$a_01_1 = {68 ec 09 71 00 58 81 ea 15 9b 40 ff 21 db e8 28 00 00 00 21 db 31 06 09 d3 81 c6 01 00 00 00 89 d3 89 d3 21 d3 39 fe 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}