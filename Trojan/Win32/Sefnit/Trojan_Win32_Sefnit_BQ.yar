
rule Trojan_Win32_Sefnit_BQ{
	meta:
		description = "Trojan:Win32/Sefnit.BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {eb 29 81 7d ec 5c 08 00 00 75 0d c7 45 } //1
		$a_01_1 = {89 51 54 83 7d 08 02 74 0f 83 7d 08 03 74 09 c7 45 } //1
		$a_03_2 = {81 c1 84 00 00 00 e9 ?? ?? ?? ?? 8b 4d ?? 81 c1 bc 00 00 00 e9 ?? ?? ?? ?? 8b 4d ?? 81 c1 f4 00 00 00 } //1
		$a_01_3 = {0f b7 51 06 40 83 c6 28 89 45 fc 3b c2 7c 8b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}