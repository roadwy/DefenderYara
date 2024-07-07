
rule Trojan_Win32_Razy_SIBB_MTB{
	meta:
		description = "Trojan:Win32/Razy.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 90 01 01 00 00 ba 90 01 04 33 c9 ff 15 90 01 04 48 89 05 90 01 04 41 b8 90 01 04 48 8d 15 90 01 04 48 8b 0d 90 01 04 ff 15 90 01 04 4c 8d 05 b1 6b 03 00 ba 90 1b 04 48 8b 0d 90 01 04 e8 90 00 } //1
		$a_03_1 = {8b 44 24 28 39 04 24 73 90 01 01 8b 04 24 48 89 44 24 90 01 01 33 d2 8b 04 24 b9 90 01 04 f7 f1 8b c2 8b c0 48 8b 4c 24 30 0f be 04 01 48 8b 4c 24 20 48 8b 54 24 90 1b 01 0f b6 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 20 88 04 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}