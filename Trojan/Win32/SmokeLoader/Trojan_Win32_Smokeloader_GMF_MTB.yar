
rule Trojan_Win32_Smokeloader_GMF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 90 01 01 03 54 24 90 01 01 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 90 01 01 81 3d 90 01 08 c7 05 90 01 08 89 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}