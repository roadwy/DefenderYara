
rule Trojan_Win32_SmokeLoader_PADJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 03 c6 d3 ea 89 45 e4 8b 45 fc c7 05 90 01 04 ee 3d ea f4 03 55 d4 89 45 f0 89 7d e8 8b 45 e4 01 45 e8 8b 45 e8 31 45 f0 8b 45 f0 33 c2 2b d8 8b c3 c1 e0 04 89 45 fc 8b 45 cc 01 45 fc 8b 4d f4 8b 45 f8 8b f3 d3 ee 03 c3 89 45 e4 03 75 dc 8b 45 e4 31 45 fc 81 3d 90 01 04 03 0b 00 00 75 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}