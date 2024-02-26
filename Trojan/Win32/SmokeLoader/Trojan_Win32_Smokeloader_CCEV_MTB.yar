
rule Trojan_Win32_Smokeloader_CCEV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 8d 04 1f 89 45 90 01 01 c7 05 90 01 08 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 83 45 90 01 02 29 45 90 01 01 83 6d 90 01 02 83 3d 90 00 } //01 00 
		$a_03_1 = {8b c2 d3 e8 03 fa 03 45 90 01 01 33 c7 31 45 90 01 01 2b 5d 90 01 01 8d 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}