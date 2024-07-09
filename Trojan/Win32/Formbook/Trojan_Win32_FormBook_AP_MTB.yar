
rule Trojan_Win32_FormBook_AP_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f0 0f b6 02 33 c1 8b 4d dc 03 4d f0 88 01 eb } //1
		$a_01_1 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 e0 52 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_FormBook_AP_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 [0-10] 66 0f 74 c1 [0-10] 66 0f 6e e6 [0-10] 66 0f 6e e9 [0-10] 0f 57 ec [0-10] 66 0f 7e e9 [0-10] 39 c1 [0-25] 90 13 0f 77 [0-10] 46 [0-15] 8b 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}