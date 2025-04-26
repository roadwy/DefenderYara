
rule Trojan_Win32_TrickBot_U{
	meta:
		description = "Trojan:Win32/TrickBot.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c2 b0 00 8b 4d e0 89 d7 f2 ae 89 c8 f7 d0 8d 48 ff 8b 45 f0 ba 00 00 00 00 f7 f1 89 d0 03 45 08 8a 00 31 f0 88 03 ff 45 f0 8b 45 f0 3b 45 10 0f 95 c0 84 c0 75 aa } //1
		$a_01_1 = {c1 e8 0d 8b 4d fc c1 e1 13 0b c1 89 45 fc 8b 45 08 0f be 00 83 f8 61 7c 0e 8b 45 08 0f be } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}