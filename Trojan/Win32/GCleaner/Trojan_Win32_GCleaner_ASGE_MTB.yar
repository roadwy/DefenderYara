
rule Trojan_Win32_GCleaner_ASGE_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ed 8b 44 24 90 01 01 33 4c 24 90 01 01 03 44 24 90 01 01 33 c1 c7 05 90 01 04 ee 3d ea f4 81 3d 90 01 04 13 02 00 00 89 4c 24 90 01 01 89 44 24 90 01 01 75 90 00 } //4
		$a_01_1 = {81 fe 38 71 20 00 7f 09 46 81 fe 72 f6 04 00 7c } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}