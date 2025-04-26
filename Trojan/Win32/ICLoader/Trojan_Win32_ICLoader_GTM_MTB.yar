
rule Trojan_Win32_ICLoader_GTM_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 c7 44 24 08 04 3a 5c 00 01 04 24 } //5
		$a_03_1 = {8d 00 01 8d ?? ?? ?? ?? ?? 00 83 ?? ?? ?? ?? 29 ca 00 01 8d 14 d6 c7 02 ?? ?? ?? ?? c7 42 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_ICLoader_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 57 4c 00 68 ?? f5 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 ?? ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}