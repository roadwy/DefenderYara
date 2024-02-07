
rule BrowserModifier_Win32_SafeSearch{
	meta:
		description = "BrowserModifier:Win32/SafeSearch,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 64 69 72 65 63 74 20 55 52 4c 3a } //01 00  Redirect URL:
		$a_01_1 = {73 61 66 65 73 65 61 72 63 68 3a 2f 2f 49 6e 66 6f 2f } //01 00  safesearch://Info/
		$a_01_2 = {6b 65 79 77 6f 72 64 3d } //01 00  keyword=
		$a_01_3 = {53 61 66 65 53 65 61 72 63 68 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  慓敦敓牡档䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_4 = {2f 73 65 61 72 63 68 2f 69 6e 64 65 78 2e 68 74 6d 6c 3f 73 72 63 68 3d 25 73 26 70 69 6e 3d 25 73 26 63 63 69 6e 66 6f 3d 25 73 } //00 00  /search/index.html?srch=%s&pin=%s&ccinfo=%s
	condition:
		any of ($a_*)
 
}