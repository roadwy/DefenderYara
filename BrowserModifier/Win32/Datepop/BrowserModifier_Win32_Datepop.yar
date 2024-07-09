
rule BrowserModifier_Win32_Datepop{
	meta:
		description = "BrowserModifier:Win32/Datepop,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 65 61 72 63 68 2e 63 6c 69 63 6b 73 74 6f 72 79 2e 63 6f 2e 6b 72 2f 73 65 61 72 63 68 5f 6b 65 79 77 6f 72 64 2e 76 68 74 3f } //1 search.clickstory.co.kr/search_keyword.vht?
		$a_00_1 = {5c 50 6f 70 64 61 74 65 00 } //1
		$a_00_2 = {26 63 70 73 70 61 73 73 3d 72 65 6c 6f 61 64 } //1 &cpspass=reload
		$a_02_3 = {61 70 70 2f 61 70 70 5f 70 6f 70 75 70 2e 70 68 70 3f [0-0a] 6b 65 79 77 6f 72 64 3d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}