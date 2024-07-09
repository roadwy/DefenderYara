
rule Trojan_Win32_Glupteba_PVS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e8 05 03 44 24 28 8d 14 1e 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 4c 24 10 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}