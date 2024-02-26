
rule Trojan_Win64_Lazy_RB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 4f 66 4b 6f 42 48 2e 28 2a 58 5f 45 78 72 30 56 70 6b 44 29 2e 70 78 72 6f 63 31 } //01 00  GOfKoBH.(*X_Exr0VpkD).pxroc1
		$a_01_1 = {1b 48 8b 05 50 b4 57 00 49 89 43 08 48 89 1d 45 } //00 00 
	condition:
		any of ($a_*)
 
}