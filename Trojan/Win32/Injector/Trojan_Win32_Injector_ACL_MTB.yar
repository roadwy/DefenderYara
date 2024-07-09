
rule Trojan_Win32_Injector_ACL_MTB{
	meta:
		description = "Trojan:Win32/Injector.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {c1 f9 02 78 ?? f3 a5 89 c1 83 e1 03 f3 a4 5f 5e } //1
		$a_02_1 = {8b d8 8b 45 d4 03 45 e0 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 6a 00 } //1
		$a_02_2 = {8b 45 f0 03 45 d8 2d ?? ?? ?? ?? 83 c0 04 89 45 fc 89 c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}