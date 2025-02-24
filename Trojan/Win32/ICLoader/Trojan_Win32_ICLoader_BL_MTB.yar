
rule Trojan_Win32_ICLoader_BL_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 8b f1 ff 15 ?? ?? 4c 00 56 ff 15 ?? ?? 4c 00 8b f0 a1 ?? ?? ?? 00 50 ff 15 ?? ?? 4c 00 68 ?? ?? 4c 00 56 ff 15 ?? ?? 4c 00 5e c3 } //4
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 4c 00 e8 ?? ?? f5 ff 0f be c0 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}