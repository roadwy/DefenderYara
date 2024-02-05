
rule Trojan_Win32_Smokeloader_GKT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 55 d8 8b 45 d8 3b 05 90 01 04 73 90 01 01 0f b6 0d 90 01 04 8b 15 90 01 04 03 55 d8 0f b6 02 33 c1 8b 0d 90 01 04 03 4d d8 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}