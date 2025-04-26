
rule Trojan_Win32_Smokeloader_FK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 8b 7d f0 8b d6 d3 ea 8d 04 37 89 45 d8 c7 05 90 a5 a9 02 ee 3d ea f4 03 55 dc 8b 45 d8 31 45 fc 33 55 fc 89 55 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}