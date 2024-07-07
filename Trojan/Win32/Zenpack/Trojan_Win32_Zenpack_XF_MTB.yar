
rule Trojan_Win32_Zenpack_XF_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.XF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 03 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 c1 e8 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 03 44 24 90 01 01 33 74 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 33 c6 81 3d 90 01 08 89 44 24 90 01 01 0f 85 90 00 } //10
		$a_01_1 = {2e 70 64 62 } //1 .pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}