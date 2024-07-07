
rule Trojan_Win32_Kovter_E{
	meta:
		description = "Trojan:Win32/Kovter.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 90 01 04 8b 55 fc 8a 54 1a ff 80 e2 f0 90 00 } //1
		$a_03_1 = {50 6a 00 6a 00 6a 24 6a 00 ff d6 50 e8 90 01 04 e8 90 01 04 e8 90 01 04 85 c0 74 0a 8b c3 90 00 } //1
		$a_03_2 = {6a 00 6a 02 6a 02 6a 00 6a 00 68 00 00 00 40 8b 45 fc e8 90 01 04 8b d8 53 e8 90 01 04 50 e8 90 01 04 8d 85 90 01 04 50 68 90 01 04 53 e8 90 01 04 53 e8 90 00 } //1
		$a_01_3 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}