
rule Trojan_Win32_Boaxxe_C{
	meta:
		description = "Trojan:Win32/Boaxxe.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {7e 47 89 45 e4 c7 45 ec 01 00 00 00 8b 45 f0 83 c0 11 6b c0 71 25 ff 00 00 00 89 45 f0 8a 45 f0 88 45 eb 8b 45 f4 e8 90 01 03 ff 8b 55 ec 8b 4d f4 8b 09 8b 5d ec 8a 4c 19 ff 32 4d eb 88 4c 10 ff ff 45 ec ff 4d e4 75 c3 90 00 } //1
		$a_02_1 = {ba 0b 00 00 00 e8 90 01 04 8d 55 90 01 01 8b 45 f4 e8 90 01 04 ff 75 90 01 01 68 90 01 04 ff 75 dc 8d 45 f4 ba 03 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}