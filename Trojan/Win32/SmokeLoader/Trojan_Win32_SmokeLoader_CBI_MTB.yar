
rule Trojan_Win32_SmokeLoader_CBI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 90 01 01 03 44 24 90 01 01 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2 90 00 } //01 00 
		$a_03_1 = {8b 54 24 14 33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 8b 3d 90 01 04 81 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}