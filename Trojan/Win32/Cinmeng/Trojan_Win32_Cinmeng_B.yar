
rule Trojan_Win32_Cinmeng_B{
	meta:
		description = "Trojan:Win32/Cinmeng.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 62 72 6f 77 73 65 72 2e 62 72 6f 77 73 65 72 2e 31 } //1 Webbrowser.browser.1
		$a_01_1 = {57 45 42 42 52 4f 57 53 45 52 4c 69 62 57 57 57 } //1 WEBBROWSERLibWWW
		$a_00_2 = {77 65 62 62 72 6f 77 73 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 敷扢潲獷牥䐮䱌䐀汬慃啮汮慯乤睯
		$a_02_3 = {38 38 41 46 2d 31 33 44 35 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d 39 46 42 38 38 36 39 38 43 46 43 31 7d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}