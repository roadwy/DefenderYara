
rule Trojan_Win32_Tibs_JG{
	meta:
		description = "Trojan:Win32/Tibs.JG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {87 d6 5a 28 d2 8a 42 01 34 ?? 3c } //1
		$a_01_1 = {66 0f 6e 04 24 66 0f 7e c2 89 d7 89 fe 89 cb e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Tibs_JG_2{
	meta:
		description = "Trojan:Win32/Tibs.JG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a ff ff d1 c9 c3 ba ?? ?? ?? ?? 66 0f 6e ?? 66 0f 7e ?? [0-02] 31 d2 } //1
		$a_03_1 = {66 0f 6e c8 66 0f 54 c1 66 0f 7e c2 8a 02 34 ?? 3c ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}