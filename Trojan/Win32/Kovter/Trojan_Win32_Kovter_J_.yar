
rule Trojan_Win32_Kovter_J_{
	meta:
		description = "Trojan:Win32/Kovter.J!!Kovter.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {37 35 36 32 40 33 42 34 35 45 31 32 39 42 39 33 } //1 7562@3B45E129B93
		$a_00_1 = {40 6f 75 68 4b 6e 64 43 6e 79 } //1 @ouhKndCny
		$a_00_2 = {40 6f 75 68 40 6d 6d 45 64 63 74 66 66 64 73 72 } //1 @ouh@mmEdctffdsr
		$a_00_3 = {40 6f 75 68 53 47 51 } //1 @ouhSGQ
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}