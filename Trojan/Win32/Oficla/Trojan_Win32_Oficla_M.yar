
rule Trojan_Win32_Oficla_M{
	meta:
		description = "Trojan:Win32/Oficla.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f6 78 c6 45 f7 00 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 90 1b 00 8d 45 f3 89 44 24 04 } //1
		$a_01_1 = {30 0c 02 40 83 f8 10 75 f1 83 c2 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Oficla_M_2{
	meta:
		description = "Trojan:Win32/Oficla.M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 53 04 8d 93 ?? 01 00 00 83 ec 08 89 14 24 ff d0 83 e8 01 83 ec 04 83 f8 01 76 22 } //1
		$a_03_1 = {ba 01 00 00 00 83 ec 08 8d 76 00 0f b6 83 ?? ?? ?? ?? 83 c3 01 89 7c 24 04 88 45 f2 8d 04 16 89 04 24 ff 15 ?? ?? ?? ?? 89 da 83 ec 08 83 fb 50 75 d9 } //1
		$a_03_2 = {ef 54 12 c6 67 ?? 5f 45 90 90 78 90 90 f5 34 98 11 } //1
		$a_01_3 = {69 6e 74 72 6f 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}