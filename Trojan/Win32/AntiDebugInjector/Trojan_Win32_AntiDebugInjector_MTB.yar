
rule Trojan_Win32_AntiDebugInjector_MTB{
	meta:
		description = "Trojan:Win32/AntiDebugInjector!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 31 d2 39 c1 0f 94 c2 8d 4c 11 01 81 f9 ?? ?? ?? ?? 7c ed 40 3d ?? ?? ?? ?? 75 d5 [0-30] 50 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}