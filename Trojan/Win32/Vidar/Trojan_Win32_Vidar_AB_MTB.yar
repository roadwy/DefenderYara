
rule Trojan_Win32_Vidar_AB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 28 03 c7 33 ca 33 c8 2b f1 8b ce c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 14 8b 44 24 30 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 37 75 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d f4 8b 4d f8 8d 04 3b d3 ef 89 45 e0 c7 05 ec bc 49 02 ee 3d ea f4 03 7d e4 8b 45 e0 31 45 fc 33 7d fc } //1
		$a_01_1 = {72 6f 62 75 62 69 7a 65 6b 69 5f 6a 6f 2e 70 64 62 } //1 robubizeki_jo.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}