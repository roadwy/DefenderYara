
rule Trojan_Win32_Smokeloader_GNT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 f5 33 c6 2b f8 81 c3 90 01 04 ff 4c 24 90 01 01 89 44 24 90 00 } //0a 00 
		$a_03_1 = {8b c7 c1 e8 90 01 01 03 44 24 90 01 01 8d 14 3b 33 ca 89 44 24 90 01 01 89 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}