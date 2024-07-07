
rule Trojan_Win32_Killav_EO{
	meta:
		description = "Trojan:Win32/Killav.EO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 71 71 2e 65 78 65 00 5c 74 65 6e 63 65 6e 74 5c 00 00 00 5c 73 61 66 65 6d 6f 6e 5c 00 00 00 5c 33 36 30 73 61 66 65 } //1
		$a_01_1 = {63 6e 7a 7a 34 34 2e 68 74 6d 6c } //1 cnzz44.html
		$a_03_2 = {68 e8 03 00 00 ff 15 90 01 04 8d 94 24 90 01 04 6a 00 52 e8 90 01 04 83 c4 08 83 f8 ff 74 29 68 04 01 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}