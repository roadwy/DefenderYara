
rule Backdoor_Win32_Talsab_F{
	meta:
		description = "Backdoor:Win32/Talsab.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed } //1
		$a_00_1 = {6c 6f 63 61 6c 2e 66 6f 6f 2e 63 6f 6d } //1 local.foo.com
		$a_00_2 = {2e 69 6e 66 6f 2f 31 73 74 65 6d 61 69 6c 2e 70 68 70 } //1 .info/1stemail.php
		$a_00_3 = {00 6e 74 6c 64 72 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}