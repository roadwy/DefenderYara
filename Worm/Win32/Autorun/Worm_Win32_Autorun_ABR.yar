
rule Worm_Win32_Autorun_ABR{
	meta:
		description = "Worm:Win32/Autorun.ABR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 1b 83 f8 01 74 16 83 f8 05 74 11 83 f8 06 74 0c 83 f8 02 75 07 53 e8 ?? ?? ?? ff } //1
		$a_01_1 = {61 63 74 69 6f 6e 3d 45 78 70 6c 6f 72 65 20 55 53 42 2d 64 72 69 76 65 20 66 69 6c 65 73 } //1 action=Explore USB-drive files
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}