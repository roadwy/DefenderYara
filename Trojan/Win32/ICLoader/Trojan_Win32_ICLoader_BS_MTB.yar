
rule Trojan_Win32_ICLoader_BS_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 00 32 c8 6a ?? 88 0d ?? ?? 63 00 8a 0d ?? ?? 63 00 80 c9 08 c0 e9 03 81 e1 ff 00 00 00 89 4c 24 04 db 44 24 04 dc 3d } //4
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 68 ?? ?? 63 00 e8 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}