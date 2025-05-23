
rule Trojan_Win32_SuspShadowAccess_D{
	meta:
		description = "Trojan:Win32/SuspShadowAccess.D,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 04 00 00 "
		
	strings :
		$a_02_0 = {6e 00 74 00 64 00 73 00 75 00 74 00 69 00 6c 00 [0-20] 61 00 63 00 20 00 69 00 6e 00 20 00 6e 00 74 00 64 00 73 00 } //100
		$a_02_1 = {64 00 73 00 64 00 62 00 75 00 74 00 69 00 6c 00 [0-20] 61 00 63 00 20 00 69 00 6e 00 20 00 6e 00 74 00 64 00 73 00 } //100
		$a_00_2 = {69 00 66 00 6d 00 } //10 ifm
		$a_00_3 = {63 00 72 00 20 00 66 00 75 00 } //10 cr fu
	condition:
		((#a_02_0  & 1)*100+(#a_02_1  & 1)*100+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=120
 
}