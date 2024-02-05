
rule Trojan_Win32_Gandcrab_PVD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.PVD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 10 02 c0 02 c0 0a 04 29 c0 e3 06 0a 5c 29 02 88 04 3e 88 54 3e 01 88 5c 3e 02 83 c1 04 83 c6 03 3b 4c 24 14 72 } //02 00 
		$a_01_1 = {8b 45 f8 2b fe 8b 4d dc 05 47 86 c8 61 83 6d f0 01 89 7d f4 89 45 f8 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}