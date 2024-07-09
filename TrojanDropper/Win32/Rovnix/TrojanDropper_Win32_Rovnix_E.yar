
rule TrojanDropper_Win32_Rovnix_E{
	meta:
		description = "TrojanDropper:Win32/Rovnix.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 f9 33 75 ?? 8b 55 10 03 55 ?? 81 3a 33 33 33 33 } //4
		$a_00_1 = {42 4b 49 6e 73 74 61 6c 6c } //1 BKInstall
		$a_00_2 = {42 00 4b 00 53 00 65 00 74 00 75 00 70 00 } //1 BKSetup
		$a_00_3 = {61 74 74 72 69 62 20 2d 72 20 2d 73 20 2d 68 25 25 31 } //1 attrib -r -s -h%%1
		$a_01_4 = {3d 46 4a 00 00 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}