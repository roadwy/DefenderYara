
rule Trojan_Win32_Tibs_JG{
	meta:
		description = "Trojan:Win32/Tibs.JG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {87 d6 5a 28 d2 8a 42 01 34 90 01 01 3c 90 00 } //01 00 
		$a_01_1 = {66 0f 6e 04 24 66 0f 7e c2 89 d7 89 fe 89 cb e8 } //01 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tibs_JG_2{
	meta:
		description = "Trojan:Win32/Tibs.JG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a ff ff d1 c9 c3 ba 90 01 04 66 0f 6e 90 01 01 66 0f 7e 90 01 01 90 02 02 31 d2 90 00 } //01 00 
		$a_03_1 = {66 0f 6e c8 66 0f 54 c1 66 0f 7e c2 8a 02 34 90 01 01 3c 90 01 01 e8 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}