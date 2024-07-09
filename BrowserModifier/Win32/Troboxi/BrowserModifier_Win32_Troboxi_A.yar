
rule BrowserModifier_Win32_Troboxi_A{
	meta:
		description = "BrowserModifier:Win32/Troboxi.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 0f b7 c9 c1 e0 10 0b c1 0f b6 4d ?? 0b c6 31 45 ec 0f b6 45 ?? 33 c1 33 c6 90 09 06 00 8a 65 ?? 8a 6d } //3
		$a_01_1 = {32 30 39 39 35 36 39 34 32 30 } //1 2099569420
		$a_01_2 = {73 65 61 72 63 68 3f 71 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d 26 63 6c 69 64 3d 31 } //1 search?q={searchTerms}&clid=1
		$a_01_3 = {25 73 3f 70 61 72 61 6d 3d 25 73 26 61 69 64 3d 25 73 } //1 %s?param=%s&aid=%s
		$a_01_4 = {75 73 65 72 5f 70 72 65 66 28 22 6b 65 79 77 6f 72 64 2e 55 52 4c } //1 user_pref("keyword.URL
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}