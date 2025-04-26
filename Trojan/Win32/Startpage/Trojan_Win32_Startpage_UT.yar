
rule Trojan_Win32_Startpage_UT{
	meta:
		description = "Trojan:Win32/Startpage.UT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {40 c1 e0 02 2b e0 8d 3c 24 51 c7 45 fc 01 00 00 00 8d 75 08 8b 1e 83 c6 04 51 e8 } //5
		$a_00_1 = {68 74 74 70 3a 2f 2f 6a 6d 70 2e 6e 65 74 2e 63 6e 2f 3f } //1 http://jmp.net.cn/?
		$a_00_2 = {53 74 61 72 74 20 50 61 67 65 } //1 Start Page
		$a_02_3 = {2e 6c 6e 6b [0-04] 68 61 6f 31 32 33 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=8
 
}