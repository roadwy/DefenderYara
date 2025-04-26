
rule Trojan_Win32_Chadivendo_STD{
	meta:
		description = "Trojan:Win32/Chadivendo.STD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 65 72 76 69 63 65 44 6c 6c [0-0a] 00 65 64 67 00 } //1
		$a_02_1 = {77 77 6c 69 62 2e 64 6c 6c [0-50] 73 63 20 73 74 61 72 74 20 22 25 73 22 } //1
		$a_00_2 = {66 32 30 33 32 2e 63 6f 6d } //1 f2032.com
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}