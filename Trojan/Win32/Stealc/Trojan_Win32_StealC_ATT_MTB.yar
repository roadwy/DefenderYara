
rule Trojan_Win32_StealC_ATT_MTB{
	meta:
		description = "Trojan:Win32/StealC.ATT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 04 89 45 fc 8b 45 d4 01 45 fc 8b 45 f8 8b 4d f0 03 c6 89 45 e4 8b c6 d3 e8 03 45 d0 89 45 f4 8b 45 e4 31 45 fc 81 3d 90 01 04 03 0b 00 00 75 90 00 } //1
		$a_03_1 = {33 45 f4 2b f8 89 45 90 01 01 89 7d e8 8b 45 cc 29 45 f8 ff 4d e0 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}