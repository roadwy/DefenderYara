
rule Trojan_Win32_Rokrat_A{
	meta:
		description = "Trojan:Win32/Rokrat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2d 2d 77 77 6a 61 75 67 68 61 6c 76 6e 63 6a 77 69 61 6a 73 2d 2d } //1 --wwjaughalvncjwiajs--
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 70 63 6c 6f 75 64 2e 63 6f 6d } //1 https://api.pcloud.com
		$a_81_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 76 6f 69 63 65 2f 6d 70 33 } //1 Content-Type: voice/mp3
		$a_81_3 = {64 69 72 20 2f 41 20 2f 53 20 25 73 20 3e 3e } //1 dir /A /S %s >>
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}