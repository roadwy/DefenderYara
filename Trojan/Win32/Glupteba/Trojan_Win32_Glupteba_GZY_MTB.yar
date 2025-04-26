
rule Trojan_Win32_Glupteba_GZY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 44 c2 03 cf a3 ?? ?? ?? ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 55 ?? 8b 45 ?? 33 d1 03 45 ?? 33 c2 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ?? 89 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}