
rule Trojan_Win32_KeyMarble{
	meta:
		description = "Trojan:Win32/KeyMarble,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 41 00 42 00 45 00 } //1 SOFTWARE\Microsoft\WABE
		$a_01_1 = {32 00 31 00 32 00 2e 00 31 00 34 00 33 00 2e 00 32 00 31 00 2e 00 34 00 33 00 } //1 212.143.21.43
		$a_01_2 = {31 00 30 00 34 00 2e 00 31 00 39 00 34 00 2e 00 31 00 36 00 30 00 2e 00 35 00 39 00 } //1 104.194.160.59
		$a_01_3 = {31 00 30 00 30 00 2e 00 34 00 33 00 2e 00 31 00 35 00 33 00 2e 00 36 00 30 00 } //1 100.43.153.60
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}