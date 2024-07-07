
rule BrowserModifier_Win32_Mispin{
	meta:
		description = "BrowserModifier:Win32/Mispin,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4d 69 6e 69 50 53 5c 4d 69 6e 69 50 53 44 } //2 %s\MiniPS\MiniPSD
		$a_01_1 = {6d 69 6e 69 70 73 2e 63 6f 2e 6b 72 } //2 minips.co.kr
		$a_01_2 = {6d 6e 6d 3d 63 6c 69 63 6b 73 74 6f 72 79 } //1 mnm=clickstory
		$a_01_3 = {69 6c 69 6b 65 63 6c 69 63 6b } //1 ilikeclick
		$a_01_4 = {68 74 74 70 3a 2f 2f 6e 61 76 65 72 00 00 00 00 26 6d 5f 75 72 6c 3d } //1
		$a_01_5 = {56 61 6c 75 65 46 72 6f 6d 43 6c 69 63 6b 3d } //1 ValueFromClick=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}