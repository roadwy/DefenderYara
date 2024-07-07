
rule Trojan_Win32_Smokeloader_GMT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 1f d3 eb 89 45 90 01 01 c7 05 90 01 04 ee 3d ea f4 03 5d 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 5d 90 01 01 81 3d 90 01 08 89 5d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}