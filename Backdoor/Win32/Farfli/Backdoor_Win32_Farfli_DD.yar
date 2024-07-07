
rule Backdoor_Win32_Farfli_DD{
	meta:
		description = "Backdoor:Win32/Farfli.DD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 11 80 ea 86 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 19 8b 45 fc 03 45 f8 88 10 eb c7 } //1
		$a_01_1 = {c6 45 f5 67 c6 45 f6 75 c6 45 f7 65 c6 45 f8 73 c6 45 f9 74 c6 45 fa 20 c6 45 fb 2f c6 45 fc 61 c6 45 fd 64 c6 45 fe 64 c6 45 ff 00 6a 00 8d 45 a0 50 ff 15 } //1
		$a_01_2 = {61 67 6d 6b 69 73 32 00 5c 5c 2e 5c 61 67 6d 6b 69 73 32 00 48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 4e } //1 条歭獩2屜尮条歭獩2瑈灴ㄯㄮ㐠㌰䘠牯楢摤乥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}