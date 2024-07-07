
rule Trojan_Win32_Smokeloader_VOO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.VOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 14 8b 4c 24 10 33 ed 8b 44 24 14 33 4c 24 18 03 44 24 2c 33 c1 c7 05 90 01 04 ee 3d ea f4 81 3d 90 01 04 13 02 00 00 89 4c 24 10 89 44 24 14 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}