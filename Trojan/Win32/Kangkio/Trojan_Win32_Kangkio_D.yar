
rule Trojan_Win32_Kangkio_D{
	meta:
		description = "Trojan:Win32/Kangkio.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 36 30 00 ce a2 b5 e3 00 } //1
		$a_01_1 = {c8 ce ce f1 b9 dc c0 ed 00 } //1
		$a_01_2 = {ce c4 bc fe bc d0 d1 a1 cf ee 00 } //1
		$a_01_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_4 = {2e 6b 61 6e 67 6b 2e 63 6e } //1 .kangk.cn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}