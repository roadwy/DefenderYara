
rule Trojan_Win32_Injector_RPA_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f8 00 00 00 00 c7 45 f8 00 00 00 00 eb 09 8b 4d f8 83 c1 01 89 4d f8 81 7d f8 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 8b 55 f8 8a 82 } //1
		$a_01_1 = {83 7d 0c 00 74 1a 8b 4d fc c6 01 00 8b 55 fc 83 c2 01 89 55 fc 8b 45 0c 83 e8 01 89 45 0c eb e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}