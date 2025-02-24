
rule Trojan_Win32_Krucky_NAC_MTB{
	meta:
		description = "Trojan:Win32/Krucky.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {6b 6b 72 75 6e 63 68 79 } //2 kkrunchy
		$a_01_1 = {0f 6f 1e 0f 6f 17 0f ed db 0f e5 d8 0f ed d9 0f 71 e3 01 0f ed d3 0f 7f 17 83 c6 08 83 c7 08 e2 df } //1
		$a_01_2 = {c1 f8 02 66 ab 80 c4 08 c1 e8 04 83 ca ff 29 c2 0f b6 c0 0f b6 d2 22 84 1b 10 ee 9c 00 22 94 1b 0f ee 9c 00 29 d0 66 ab 83 fb 01 } //1
		$a_01_3 = {83 f3 01 8a 24 1f 80 fc 02 76 0f 0f b6 c4 8b 04 85 0b ea 9c 00 c1 e0 02 fe cc 83 f3 01 8a 04 1f 40 3c 28 76 02 b0 28 f6 c3 01 74 02 86 c4 57 89 ca f2 66 af 74 03 42 66 af f7 d1 01 d1 66 89 47 fe 88 0e 46 89 d1 5f 43 80 ff 02 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}