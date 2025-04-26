
rule Trojan_Win32_Clicker_PADL_MTB{
	meta:
		description = "Trojan:Win32/Clicker.PADL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6c 69 63 6b 69 6e 66 6f 2e 64 6c 6c 3f 67 65 74 6b 65 79 77 6f 72 64 } //1 clickinfo.dll?getkeyword
		$a_01_1 = {52 65 66 65 72 43 6c 69 63 6b 2e 63 6c 69 63 6b 28 29 } //1 ReferClick.click()
		$a_01_2 = {53 65 74 42 61 69 64 75 53 65 61 72 63 68 4b 65 79 57 6f 72 64 } //1 SetBaiduSearchKeyWord
		$a_01_3 = {42 61 69 64 75 43 6c 69 63 6b } //1 BaiduClick
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}