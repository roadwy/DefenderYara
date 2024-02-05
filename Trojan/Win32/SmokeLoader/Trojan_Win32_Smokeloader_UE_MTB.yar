
rule Trojan_Win32_Smokeloader_UE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.UE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 03 c1 83 e0 90 01 01 0f b6 80 90 01 04 30 41 90 01 01 83 c1 90 01 01 8d 04 0e 3d 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}