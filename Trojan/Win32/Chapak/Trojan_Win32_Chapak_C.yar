
rule Trojan_Win32_Chapak_C{
	meta:
		description = "Trojan:Win32/Chapak.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {eb 18 81 fe e6 26 00 00 7d 08 6a 00 ff 15 90 02 03 00 e8 90 02 04 30 04 37 83 ee 01 79 e3 90 00 } //1
		$a_03_1 = {81 fe 51 a1 00 00 75 05 e8 90 02 03 ff 46 81 fe 5b 54 5a 00 7c ea 64 a1 2c 00 00 00 90 00 } //1
		$a_03_2 = {0f b6 c2 03 c8 0f b6 c1 5e 8a 80 90 02 03 00 c3 90 00 } //1
		$a_01_3 = {79 00 69 00 79 00 61 00 70 00 65 00 6c 00 69 00 } //1 yiyapeli
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}