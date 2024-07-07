
rule Trojan_Win32_Amadey_MOK_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca c1 e1 90 01 01 89 44 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b c2 c1 e8 90 01 01 03 c3 8d 0c 17 33 c8 8b 44 24 90 01 01 33 c1 2b f0 81 3d 90 01 08 c7 05 90 01 08 c7 05 90 01 08 74 90 01 01 81 c7 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}