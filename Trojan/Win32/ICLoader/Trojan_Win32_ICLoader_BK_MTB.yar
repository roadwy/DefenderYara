
rule Trojan_Win32_ICLoader_BK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 14 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8d 54 24 04 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 52 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 04 db 44 24 04 } //4
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 66 00 e8 ?? ?? fb ff 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}