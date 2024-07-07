
rule Trojan_Win32_AveMariaRAT_PABD_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.PABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 99 f7 7d e4 89 55 d8 81 7d 08 00 00 00 01 74 1b 8b 45 f8 03 45 08 0f be 08 8b 55 d8 0f be 44 15 10 33 c8 8b 55 f8 03 55 08 88 0a eb bf } //1
		$a_01_1 = {8a 04 02 88 44 0d 04 b9 01 00 00 00 6b d1 03 b8 01 00 00 00 6b c8 03 8b 45 0c 8a 14 10 88 54 0d 04 b8 01 00 00 00 6b c8 00 8b 55 0c c6 04 0a c2 b8 01 00 00 00 c1 e0 00 8b 4d 0c c6 04 01 10 ba 01 00 00 00 d1 e2 8b 45 0c c6 04 10 00 b9 01 00 00 00 6b d1 03 8b 45 0c c6 04 10 90 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}