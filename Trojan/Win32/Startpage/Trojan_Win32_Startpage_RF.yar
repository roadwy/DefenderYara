
rule Trojan_Win32_Startpage_RF{
	meta:
		description = "Trojan:Win32/Startpage.RF,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f8 01 1b db 43 84 db 75 0a } //01 00 
		$a_01_1 = {d4 da cf df 2e 6c 6e 6b } //02 00 
		$a_01_2 = {77 77 77 2e 79 78 74 69 6e 67 2e 63 6e 2f } //02 00  www.yxting.cn/
		$a_01_3 = {67 6c 2e 32 36 37 30 2e 63 6f 6d 2f } //01 00  gl.2670.com/
		$a_01_4 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 41 } //01 00  LookupAccountSidA
		$a_01_5 = {46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 } //00 00  Files\Internet Explorer\iexplore
	condition:
		any of ($a_*)
 
}