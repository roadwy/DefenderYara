
rule Trojan_Win32_RedLine_MBED_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 01 09 c8 88 44 24 1f 8b 4c 24 20 0f b6 44 24 1f 29 c8 88 44 24 1f 0f b6 4c 24 1f 31 c0 29 c8 88 44 24 1f 8b 4c 24 20 0f b6 44 24 1f 29 c8 88 44 24 1f } //1
		$a_01_1 = {f6 17 80 2f 4a 47 e2 } //1
		$a_01_2 = {6e 7a 6a 6c 63 78 6c 6f 64 75 71 74 6a 66 67 70 74 71 61 61 78 63 72 79 74 72 7a 64 66 79 68 6e 64 64 63 6c 69 7a 66 6b 67 77 6c 75 69 75 } //1 nzjlcxloduqtjfgptqaaxcrytrzdfyhnddclizfkgwluiu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}