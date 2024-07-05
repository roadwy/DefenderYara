
rule Trojan_Win32_Glupteba_AAX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 f8 8b 4d fc 8b 45 f8 33 4d f0 03 45 d8 33 c1 c7 05 90 01 04 ee 3d ea f4 81 3d 90 01 04 13 02 00 00 89 4d fc 89 45 f8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}