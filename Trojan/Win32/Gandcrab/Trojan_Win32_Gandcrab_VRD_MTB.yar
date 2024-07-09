
rule Trojan_Win32_Gandcrab_VRD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.VRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a c1 8a d9 24 ?? 80 e1 ?? c0 e0 ?? 0a 44 2e ?? 8b 6c 24 ?? 02 c9 02 c9 0a 0c 2e c0 e3 ?? 0a 5c 2e ?? 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 ?? 42 3b 74 24 ?? 72 } //1
		$a_02_1 = {0f be 1c 3e 81 c3 01 10 00 00 e8 ?? ?? ?? ?? fe cb 32 c3 88 04 3e 46 3b f5 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}