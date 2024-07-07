
rule Trojan_Win32_Smokeloader_GMB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 ee 03 c7 89 45 90 01 01 c7 05 90 01 04 ee 3d ea f4 03 75 90 01 01 8b 45 90 01 01 31 45 90 01 01 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}