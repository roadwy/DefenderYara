
rule Trojan_Win32_Lampa_A{
	meta:
		description = "Trojan:Win32/Lampa.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8a 00 30 01 8b 0d 90 01 04 41 81 f9 ae 01 00 00 89 0d 90 1b 00 0f 82 90 00 } //1
		$a_03_1 = {8b 09 8a 09 30 08 a1 90 01 04 40 3d ae 01 00 00 a3 90 01 04 0f 82 90 00 } //1
		$a_03_2 = {6a 40 68 00 02 00 00 ff 35 90 01 04 ff 15 90 01 04 a1 90 01 04 2b 05 90 01 04 2d 00 50 0f 00 a3 90 01 04 79 0c a1 90 01 04 a3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}