
rule Trojan_Win32_Tracur_AK{
	meta:
		description = "Trojan:Win32/Tracur.AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 04 8b f0 68 00 10 00 00 8d 46 01 50 6a 00 ff 15 } //2
		$a_03_1 = {89 43 04 3b c6 74 33 8b 43 08 8d 8d 90 01 04 51 c1 e0 05 90 00 } //2
		$a_01_2 = {73 65 61 72 63 68 5f 71 75 65 72 79 3d } //1 search_query=
		$a_01_3 = {53 68 6d 5f 25 73 } //1 Shm_%s
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}