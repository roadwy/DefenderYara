
rule Trojan_Win32_Smokeloader_GKM_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 03 45 f4 89 45 0c 8b 4d e0 83 0d 90 01 06 c3 c1 e8 05 03 45 ec 03 f1 33 f0 33 75 0c c7 05 90 01 04 19 36 6b ff 89 75 fc 8b 45 fc 29 45 08 81 3d 90 01 04 93 00 00 00 74 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}