
rule Trojan_Win32_Glupteba_GZY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f 44 c2 03 cf a3 90 01 04 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 8b 55 90 01 01 8b 45 90 01 01 33 d1 03 45 90 01 01 33 c2 c7 05 90 01 04 ee 3d ea f4 81 3d 90 01 04 13 02 00 00 89 55 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}