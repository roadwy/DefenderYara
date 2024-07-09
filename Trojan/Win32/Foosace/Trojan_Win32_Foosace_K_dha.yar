
rule Trojan_Win32_Foosace_K_dha{
	meta:
		description = "Trojan:Win32/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 c1 74 0e 00 00 00 c7 44 c1 70 ?? ?? ?? ?? c7 44 c1 7c 0f 00 00 00 c7 44 c1 78 ?? ?? ?? ?? c7 84 c1 84 00 00 00 11 00 00 00 } //1
		$a_03_1 = {89 81 74 01 00 00 85 c0 0f 84 ?? 00 00 00 8b 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 ff d6 8b 0d ?? ?? ?? ?? 89 81 58 01 00 00 } //1
		$a_03_2 = {8b 82 e0 00 00 00 ff d0 83 c4 14 8d 4d ?? 51 8b 15 ?? ?? ?? ?? 8b 42 10 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}