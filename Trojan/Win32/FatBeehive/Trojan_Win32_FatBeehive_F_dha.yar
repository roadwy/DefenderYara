
rule Trojan_Win32_FatBeehive_F_dha{
	meta:
		description = "Trojan:Win32/FatBeehive.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {63 68 65 63 ?? 67 20 20 } //1
		$a_03_1 = {66 89 84 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 0f 28 05 ?? ?? ?? ?? 0f 29 84 24 ?? ?? ?? ?? 0f 28 05 } //1
		$a_03_2 = {4e 74 43 72 65 61 74 65 ?? 68 72 65 61 64 45 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}