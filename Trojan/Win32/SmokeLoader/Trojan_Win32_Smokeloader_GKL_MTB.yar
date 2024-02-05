
rule Trojan_Win32_Smokeloader_GKL_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 8a 80 90 01 04 30 81 90 01 04 41 81 f9 90 01 04 72 90 00 } //0a 00 
		$a_03_1 = {8b c3 83 e0 03 8a 80 90 01 04 30 83 90 01 04 43 81 fb 90 01 04 72 90 00 } //01 00 
		$a_03_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}