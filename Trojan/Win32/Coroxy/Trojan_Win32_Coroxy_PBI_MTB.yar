
rule Trojan_Win32_Coroxy_PBI_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 89 c6 89 d7 89 c8 39 f7 90 13 8d 74 31 ?? 8d 7c 39 ?? c1 f9 02 78 ?? fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //1
		$a_03_1 = {8b 45 d8 89 18 e8 ?? ?? ?? ?? 8b 5d cc 03 5d ac 81 eb ?? ?? ?? ?? 03 5d e8 2b d8 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}