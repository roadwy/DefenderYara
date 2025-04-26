
rule Trojan_Win32_CryptInject_RBC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {4e 11 00 00 c7 44 24 ?? ?? ?? ?? ?? 75 90 09 06 00 81 3d } //1
		$a_03_1 = {89 44 24 34 75 90 09 18 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 ?? a1 } //10
		$a_03_2 = {89 44 24 34 75 90 09 13 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 89 44 24 ?? 8b } //10
		$a_03_3 = {c3 04 00 00 75 90 09 0b 00 8b ?? c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*1) >=12
 
}