
rule Trojan_Win32_Seepeed_A{
	meta:
		description = "Trojan:Win32/Seepeed.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 18 8b 55 fc c6 04 39 01 0f b6 0c 18 88 04 11 48 79 eb } //1
		$a_01_1 = {88 14 30 8b d1 c1 fa 08 88 54 30 01 88 4c 30 02 83 c0 03 33 c9 33 ff } //1
		$a_00_2 = {8b c1 c1 e8 02 8a 04 38 88 02 83 e1 03 8b c6 c1 e8 04 c1 e1 04 0b c1 8a 04 38 88 42 01 } //1
		$a_01_3 = {00 64 6c 6c 2e 64 6c 6c 00 53 76 63 4d 61 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}