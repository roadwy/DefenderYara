
rule Trojan_Win32_QakBot_BB_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 5d a0 6a 00 e8 [0-04] 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_QakBot_BB_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 73 56 36 43 62 47 58 42 47 } //3 CsV6CbGXBG
		$a_01_1 = {44 4c 44 52 35 46 55 59 6a } //3 DLDR5FUYj
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_01_3 = {53 74 72 46 6f 72 6d 61 74 42 79 74 65 53 69 7a 65 45 78 } //3 StrFormatByteSizeEx
		$a_01_4 = {53 65 74 53 74 64 48 61 6e 64 6c 65 } //3 SetStdHandle
		$a_01_5 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 } //3 FlushFileBuffers
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}