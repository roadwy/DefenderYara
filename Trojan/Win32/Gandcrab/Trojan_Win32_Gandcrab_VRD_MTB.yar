
rule Trojan_Win32_Gandcrab_VRD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.VRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a c1 8a d9 24 90 01 01 80 e1 90 01 01 c0 e0 90 01 01 0a 44 2e 90 01 01 8b 6c 24 90 01 01 02 c9 02 c9 0a 0c 2e c0 e3 90 01 01 0a 5c 2e 90 01 01 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 90 01 01 42 3b 74 24 90 01 01 72 90 00 } //01 00 
		$a_02_1 = {0f be 1c 3e 81 c3 01 10 00 00 e8 90 01 04 fe cb 32 c3 88 04 3e 46 3b f5 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}