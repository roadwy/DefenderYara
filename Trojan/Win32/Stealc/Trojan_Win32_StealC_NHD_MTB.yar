
rule Trojan_Win32_StealC_NHD_MTB{
	meta:
		description = "Trojan:Win32/StealC.NHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8d 04 37 89 45 d8 c7 05 90 01 04 ee 3d ea f4 03 55 dc 8b 45 d8 31 45 fc 33 55 fc 89 55 d8 8b 45 d8 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d 90 01 04 0c 75 90 00 } //1
		$a_03_1 = {d3 ee 03 75 d0 81 3d 90 01 04 21 01 00 00 75 07 53 ff 15 90 01 04 31 75 fc 8b 45 fc 29 45 ec 81 45 f0 47 86 c8 61 ff 4d e4 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}