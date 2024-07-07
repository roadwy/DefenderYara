
rule TrojanSpy_Win32_Webmoner_S{
	meta:
		description = "TrojanSpy:Win32/Webmoner.S,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 6d 6f 6e 65 79 2e 65 78 65 } //1 webmoney.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 70 61 73 73 70 6f 72 74 2e 77 65 62 6d 6f 6e 65 79 2e 72 75 2f 61 73 70 2f 63 65 72 74 76 69 65 77 2e 61 73 70 3f 77 6d 69 64 3d } //1 http://passport.webmoney.ru/asp/certview.asp?wmid=
		$a_01_2 = {53 65 6e 64 20 57 65 62 4d 6f 6e 65 79 } //1 Send WebMoney
		$a_01_3 = {64 69 6c 6c 6c 2e 64 6c 6c } //1 dilll.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}