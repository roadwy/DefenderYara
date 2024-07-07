
rule Trojan_Win32_WebSearch_F{
	meta:
		description = "Trojan:Win32/WebSearch.F,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_00_0 = {2e 72 75 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 62 68 6f 2e 70 68 70 } //10 .ru/search/searchbho.php
		$a_00_1 = {3c 21 2d 2d 72 65 73 75 6c 74 73 2d 2d 3e } //10 <!--results-->
		$a_01_2 = {53 65 61 72 63 68 42 48 4f 2e 53 45 4f 42 48 4f 2e 31 } //10 SearchBHO.SEOBHO.1
		$a_00_3 = {73 65 61 72 63 68 2e 79 61 68 6f 6f 2e 63 6f 6d } //1 search.yahoo.com
		$a_00_4 = {6e 6f 76 61 2e 72 61 6d 62 6c 65 72 2e 72 75 } //1 nova.rambler.ru
		$a_00_5 = {79 61 6e 64 65 78 2e 72 75 } //1 yandex.ru
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=31
 
}