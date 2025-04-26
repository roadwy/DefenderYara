
rule Trojan_Win32_Xzof_A{
	meta:
		description = "Trojan:Win32/Xzof.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {8d 70 01 90 8a 10 40 84 d2 75 f9 2b c6 3b c8 7c e3 b8 } //1
		$a_01_1 = {eb 06 8d 9b 00 00 00 00 0f b6 4c 34 34 51 8d 54 24 20 68 } //1
		$a_01_2 = {66 6f 7a 78 00 } //1
		$a_01_3 = {5d 58 4a 4f 45 50 58 54 } //1 ]XJOEPXT
		$a_01_4 = {5d 55 66 6e 71 } //1 ]Ufnq
		$a_01_5 = {64 73 7a 71 2f 71 69 71 } //1 dszq/qiq
		$a_01_6 = {63 72 79 70 2e 70 68 70 } //1 cryp.php
		$a_01_7 = {74 69 34 6d 6d 7a 71 76 6f 6c 2f 64 70 6e } //1 ti4mmzqvol/dpn
		$a_01_8 = {73 68 33 6c 6c 79 70 75 6e 6b 2e 63 6f 6d } //1 sh3llypunk.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}