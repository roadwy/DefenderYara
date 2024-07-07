
rule TrojanClicker_Win32_Delf_MB{
	meta:
		description = "TrojanClicker:Win32/Delf.MB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 69 00 6e 00 73 00 64 00 69 00 72 00 65 00 63 00 74 00 2e 00 6e 00 65 00 74 00 2f 00 31 00 2f 00 74 00 64 00 73 00 36 00 2e 00 70 00 68 00 70 00 } //3 http://ginsdirect.net/1/tds6.php
		$a_01_1 = {30 20 63 6c 69 63 6b 73 2c 20 62 65 20 6c 75 63 6b 79 20 6e 65 78 74 20 74 69 6d 65 } //2 0 clicks, be lucky next time
		$a_01_2 = {62 65 67 69 6e 20 25 64 20 63 6c 69 63 6b 73 } //2 begin %d clicks
		$a_01_3 = {77 69 6e 64 6f 77 2e 63 6f 6e 66 69 72 6d 3d 66 75 6e 63 74 69 6f 6e 28 29 7b 7d 3b 77 69 6e 64 6f 77 2e } //1 window.confirm=function(){};window.
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}