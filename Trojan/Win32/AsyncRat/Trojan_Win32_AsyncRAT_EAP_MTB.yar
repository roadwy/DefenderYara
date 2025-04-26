
rule Trojan_Win32_AsyncRAT_EAP_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.EAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {97 a6 69 65 9c 72 06 3e 32 f7 46 29 b3 58 6c 61 81 23 d2 b9 2c 9b 32 81 27 d8 42 ae b2 83 2b d4 23 0b d2 23 b7 78 82 1c 68 81 fe e2 } //2
		$a_01_1 = {86 43 38 90 65 3f 65 83 38 00 41 11 d4 40 11 fa 82 74 8a 6f 39 aa 4a 17 2a e0 17 2c 81 1a 5c e7 11 71 07 2b cb 63 92 26 e9 3a ee 31 78 3a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}