
rule Trojan_Win32_ICLoader_BM_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 8b f1 50 ff 15 ?? ?? 65 00 56 ff 15 ?? ?? 65 00 8b f0 6a 00 ff 15 ?? ?? 65 00 68 ?? ?? ?? 00 56 ff 15 ?? ?? 65 00 a3 ?? ?? ?? 00 56 ff 15 ?? ?? 65 00 8b 44 24 04 5e 59 c3 } //4
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 66 00 e8 ?? ?? fb ff 89 45 fc e9 } //1
		$a_03_2 = {56 50 ff 15 ?? ?? 65 00 8a 0d ?? ?? 66 00 a0 ?? ?? 66 00 22 c1 8b 0d ?? ?? 66 00 a2 ?? ?? 66 00 a1 ?? ?? 66 00 8b d0 6a 00 c1 ea 02 2b ca 33 d2 8a 15 } //4
		$a_03_3 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? fb ff 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1+(#a_03_2  & 1)*4+(#a_03_3  & 1)*1) >=5
 
}