
rule Trojan_Win32_StealC_MZX_MTB{
	meta:
		description = "Trojan:Win32/StealC.MZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 45 e8 8b 45 e8 89 45 ec 8b 75 f4 8b 4d f0 8b 45 ec 31 45 fc d3 ee 03 75 dc 81 3d 90 01 04 21 01 00 00 75 90 00 } //1
		$a_03_1 = {33 c6 89 45 fc 2b f8 8b 45 d4 29 45 f8 83 6d e4 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}