
rule Trojan_Win32_Smokeloader_GKQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 45 90 01 01 03 f3 33 c6 33 45 90 01 01 c7 05 90 01 04 19 36 6b ff 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 81 3d 90 01 04 93 00 00 00 74 90 01 01 81 45 90 01 01 47 86 c8 61 ff 4d 90 01 01 8b 45 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}