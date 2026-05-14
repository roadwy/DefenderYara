
rule Trojan_Win32_Amadey_NMP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b c8 8d 04 0a 33 d2 f7 f3 8b 5d ec 8b cb 83 7b 14 10 72 02 8b 0b 8a 04 32 8b 75 f4 88 04 31 46 89 75 f4 3b 75 f0 } //1
		$a_01_1 = {8b 45 e8 8a d4 c0 ea 04 8a c8 c0 e1 02 80 e2 03 02 d1 8a c4 88 55 e4 8a 55 ea 8a ca c0 e0 04 c0 e9 02 80 e1 0f c0 e2 06 } //1
		$a_01_2 = {d1 ea 2b c2 3b c8 76 07 bb ff ff ff 7f eb 08 8d 04 0a 3b d8 0f 42 d8 33 c9 8b c3 83 c0 01 0f 92 c1 f7 d9 0b c8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}