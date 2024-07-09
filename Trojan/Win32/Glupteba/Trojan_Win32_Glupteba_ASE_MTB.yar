
rule Trojan_Win32_Glupteba_ASE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 8d 04 3b d3 ef 89 45 f0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d ?? 8b 45 f0 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 7d f0 75 } //1
		$a_01_1 = {d3 e8 8d 3c 13 03 45 e0 33 c7 31 45 fc 8b 4d fc 8d 45 ec e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}