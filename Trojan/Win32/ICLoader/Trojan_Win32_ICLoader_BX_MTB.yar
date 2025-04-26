
rule Trojan_Win32_ICLoader_BX_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 00 8a 0d [0-0a] 32 c8 [0-01] 88 0d ?? ?? 89 00 8a 0d ?? ?? 89 00 80 c9 0c c0 e9 02 81 e1 ff 00 00 00 89 4c 24 ?? db 44 24 ?? dc 3d } //4
		$a_01_1 = {55 8b ec 83 ec 0c 53 56 57 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}