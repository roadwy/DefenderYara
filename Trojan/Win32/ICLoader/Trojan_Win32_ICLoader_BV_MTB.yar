
rule Trojan_Win32_ICLoader_BV_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {3b c5 89 44 24 0c 0f 84 83 00 00 00 8b 4c 24 ?? 68 24 00 01 00 51 50 ff 15 ?? ?? ?? 00 8b f0 8b fe 3b f5 89 7c 24 } //4
		$a_01_1 = {55 8b ec 83 ec 0c 53 56 57 } //1
		$a_03_2 = {32 c8 56 88 0d ?? ?? 8a 00 8a 0d ?? ?? 8a 00 80 c9 0c 6a 0a c0 e9 02 81 e1 ff 00 00 00 89 4c 24 08 db 44 24 08 c7 44 24 08 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_03_2  & 1)*4) >=5
 
}