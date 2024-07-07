
rule Trojan_Win32_Rhadamanthys_MNV_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.MNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 cb 33 ca 03 c5 33 c1 81 3d 90 01 08 89 4c 24 10 89 44 24 90 01 01 c7 05 90 01 08 75 90 00 } //1
		$a_03_1 = {8b ce c1 e9 05 c7 05 90 01 08 c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8d 14 37 31 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}