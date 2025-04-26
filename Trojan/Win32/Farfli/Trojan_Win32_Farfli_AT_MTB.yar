
rule Trojan_Win32_Farfli_AT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 78 79 39 39 39 2e 63 6f 6d } //1 www.xy999.com
		$a_01_1 = {77 77 77 2e 61 70 70 73 70 65 65 64 2e 63 6f 6d } //1 www.appspeed.com
		$a_01_2 = {41 41 44 7a 36 41 41 42 42 59 2f 7a 78 75 44 51 7a 4f 58 53 34 64 61 50 41 4e 4c 68 35 63 62 51 30 71 38 } //1 AADz6AABBY/zxuDQzOXS4daPANLh5cbQ0q8
		$a_01_3 = {38 39 4c 56 7a 75 4c 4c 34 36 38 } //1 89LVzuLL468
		$a_01_4 = {6b 75 67 65 33 39 30 37 40 73 69 6e 61 2e 63 6f 6d } //1 kuge3907@sina.com
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}